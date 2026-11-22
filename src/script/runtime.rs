use super::Target;
use crate::Result;
use rquickjs::{
    BigInt, CatchResultExt, Context, Ctx, Exception, Function, Module, Object, Runtime, Value,
    function::{Opt, Rest},
};
use serde_json::{Value as Json, json};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

const JSON_REPLACER: &str =
    "(key, value) => typeof value === 'bigint' ? { $bigint: value.toString() } : value";
const OUTPUT_LIMIT: usize = 512 * 1024;

pub(super) fn serialize_return<'js>(ctx: &Ctx<'js>, value: Value<'js>) -> rquickjs::Result<Json> {
    let replacer: Function = ctx.eval(JSON_REPLACER)?;
    serialize(ctx, value, &replacer, OUTPUT_LIMIT)
}

pub(super) fn call_default<'js>(
    ctx: &Ctx<'js>,
    namespace: Object<'js>,
) -> rquickjs::Result<Value<'js>> {
    let main: Value = namespace.get("default")?;
    if main.is_undefined() {
        return Ok(main);
    }
    main.into_function()
        .ok_or_else(|| Exception::throw_message(ctx, "The default export must be a function"))?
        .call(())
}

pub(super) struct Execution {
    pub stop_reason: &'static str,
    pub output: Vec<Json>,
    pub issue: Option<String>,
    pub return_value: Json,
}

pub(super) fn as_js<'js>(ctx: &Ctx<'js>, json: Json) -> rquickjs::Result<Value<'js>> {
    ctx.json_parse(json.to_string())
}

pub(super) fn frame_handle<'js>(ctx: &Ctx<'js>, frame: Value<'js>) -> rquickjs::Result<String> {
    if let Some(frame) = frame.as_object() {
        frame.get("handle")
    } else {
        rquickjs::FromJs::from_js(ctx, frame)
    }
}

pub(super) fn expansion(
    options: Option<&Object<'_>>,
) -> rquickjs::Result<Option<crate::rpc::InspectExpansion>> {
    options
        .map(|options| -> rquickjs::Result<_> { options.get::<_, Option<Object>>("expand") })
        .transpose()
        .map(Option::flatten)?
        .map(|page| {
            Ok(crate::rpc::InspectExpansion {
                offset: page.get::<_, Option<u32>>("offset")?.unwrap_or_default(),
                limit: page.get("limit")?,
            })
        })
        .transpose()
}

pub(super) fn debug_value<'js>(ctx: &Ctx<'js>, report: Json) -> rquickjs::Result<Value<'js>> {
    let object = ctx
        .json_parse(report.to_string())?
        .into_object()
        .ok_or_else(|| Exception::throw_message(ctx, "invalid debugger report"))?;
    normalize_debug_value(ctx, &object, &report)?;
    Ok(object.into_value())
}

fn normalize_debug_value<'js>(
    ctx: &Ctx<'js>,
    object: &Object<'js>,
    report: &Json,
) -> rquickjs::Result<()> {
    let data = &report["result"];
    if !data.is_null() {
        let value: Object<'js> = object.get("result")?;
        for name in ["address", "value"] {
            if let Some(text) = data[name].as_str() {
                let bigint = if let Some(hex) = text.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                        .ok()
                        .map(|n| BigInt::from_u64(ctx.clone(), n))
                } else if let Ok(n) = text.parse::<i64>() {
                    Some(BigInt::from_i64(ctx.clone(), n))
                } else {
                    text.parse::<u64>()
                        .ok()
                        .map(|n| BigInt::from_u64(ctx.clone(), n))
                };
                if let Some(bigint) = bigint {
                    value.set(name, bigint?)?;
                }
            }
        }
    }
    if let Some(children) = report["children"]["items"].as_array() {
        let result: Object = object.get("children")?;
        let items: rquickjs::Array = result.get("items")?;
        for (i, child) in children.iter().enumerate() {
            let row: Object = items.get(i)?;
            normalize_debug_value(ctx, &row.get::<_, Object>("value")?, &child["value"])?;
        }
    }
    Ok(())
}

fn check_deadline(ctx: &Ctx<'_>, deadline: Instant) -> rquickjs::Result<()> {
    if Instant::now() >= deadline {
        return Err(Exception::throw_message(
            ctx,
            "script execution exceeded timeout_ms",
        ));
    }
    Ok(())
}

pub(super) fn execute(js: String, target: Arc<Target>, budget: Duration) -> Result<Execution> {
    let runtime = Runtime::new()?;
    runtime.set_memory_limit(16 * 1024 * 1024);
    runtime.set_max_stack_size(256 * 1024);
    let deadline = Instant::now() + budget;
    let interrupted = Rc::new(Cell::new(false));
    let hit_limit = Rc::clone(&interrupted);
    runtime.set_interrupt_handler(Some(Box::new(move || {
        let expired = Instant::now() >= deadline;
        hit_limit.set(expired);
        expired
    })));
    let context = Context::full(&runtime)?;
    let output = Rc::new(RefCell::new(Vec::new()));
    let output_bytes = Rc::new(Cell::new(0));
    let evaluation = context.with(|ctx| {
        let result = evaluate(
            ctx.clone(),
            &js,
            target,
            Rc::clone(&output),
            output_bytes,
            deadline,
        );
        result
            .catch(&ctx)
            .map_err(|e| e.to_string().chars().take(4096).collect::<String>())
    });
    // Finish promise reactions queued by a module that has already evaluated.
    let evaluation = evaluation.and_then(|value| {
        while Instant::now() < deadline {
            match runtime.execute_pending_job() {
                Ok(true) => {}
                Ok(false) => return Ok(value),
                Err(_) => return Err("uncaught error in a QuickJS job".into()),
            }
        }
        Err("script execution exceeded timeout_ms".into())
    });
    let (stop_reason, issue, return_value) = match evaluation {
        Ok(value) => ("completed", None, value),
        Err(_) if interrupted.get() || Instant::now() >= deadline => (
            "timed_out",
            Some("script execution exceeded timeout_ms".into()),
            Json::Null,
        ),
        Err(message) => ("runtime_error", Some(message), Json::Null),
    };
    Ok(Execution {
        stop_reason,
        output: output.take(),
        issue,
        return_value,
    })
}

fn evaluate<'js>(
    ctx: Ctx<'js>,
    js: &str,
    target: Arc<Target>,
    entries: Rc<RefCell<Vec<Json>>>,
    output_bytes: Rc<Cell<usize>>,
    deadline: Instant,
) -> rquickjs::Result<Json> {
    let globals = ctx.globals();
    for global in ["SharedArrayBuffer", "Atomics"] {
        globals.remove(global)?;
    }
    let dbg = Object::new(ctx.clone())?;
    let print_entries = Rc::clone(&entries);
    let print_bytes = Rc::clone(&output_bytes);
    super::debugger::bind(
        &ctx,
        &dbg,
        target,
        deadline,
        |ctx| ctx.globals().get("DataView"),
        move |ctx, expression, label, report| {
            push_output(
                ctx,
                &print_entries,
                &print_bytes,
                json!({"label": label, "expression": expression, "value": report}),
            )
        },
    )?;
    let emit_entries = Rc::clone(&entries);
    let emit_bytes = Rc::clone(&output_bytes);
    dbg.set(
        "emit",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>,
                  label: String,
                  value: Value<'js>,
                  Opt(options): Opt<Object<'js>>| {
                use super::breakpoint::{ENCODE_VALUE, FieldValue, OutputField};
                check_deadline(&ctx, deadline)?;
                let kind: Option<String> = options
                    .map(|object| object.get("kind"))
                    .transpose()?
                    .flatten();
                let encode: Function = ctx.eval(ENCODE_VALUE)?;
                let field = OutputField {
                    label,
                    value: FieldValue::read(&ctx, &encode, value, kind.as_deref())?,
                };
                push_output(&ctx, &emit_entries, &emit_bytes, field.json())
            },
        )?,
    )?;
    globals.set("dbg", dbg)?;

    let replacer: Function = ctx.eval(JSON_REPLACER)?;
    let console = Object::new(ctx.clone())?;
    let log_entries = Rc::clone(&entries);
    let log_bytes = Rc::clone(&output_bytes);
    console.set(
        "log",
        Function::new(
            ctx.clone(),
            move |ctx: Ctx<'js>, Rest(args): Rest<Value<'js>>| {
                check_deadline(&ctx, deadline)?;
                let values = rquickjs::Array::new(ctx.clone())?;
                for (index, value) in args.into_iter().enumerate() {
                    values.set(index, value)?;
                }
                let replacer: Function = ctx.eval(JSON_REPLACER)?;
                let values = serialize(
                    &ctx,
                    values.into_value(),
                    &replacer,
                    OUTPUT_LIMIT - log_bytes.get(),
                )?;
                push_output(
                    &ctx,
                    &log_entries,
                    &log_bytes,
                    json!({ "kind": "console", "values": values }),
                )
            },
        )?,
    )?;
    globals.set("console", console)?;

    let (module, promise) = Module::declare(ctx.clone(), "script.js", js.as_bytes())?.eval()?;
    promise.finish::<()>()?;
    let value = call_default(&ctx, module.namespace()?)?;
    let value = match value.clone().into_promise() {
        Some(promise) => promise.finish()?,
        None => value,
    };
    serialize(&ctx, value, &replacer, OUTPUT_LIMIT - output_bytes.get())
}

pub(super) fn memory_view<'js>(
    ctx: &Ctx<'js>,
    address: BigInt<'js>,
    length: f64,
    constructor: &rquickjs::function::Constructor<'js>,
    read: impl FnOnce(u64, &mut [u8]) -> rquickjs::Result<usize>,
) -> rquickjs::Result<Object<'js>> {
    use rquickjs::{ArrayBuffer, Coerced, FromJs};
    let Coerced(address) = Coerced::<String>::from_js(ctx, address.into_value())?;
    let address: u64 = address.parse().map_err(|_| {
        Exception::throw_range(ctx, "address must fit in an unsigned 64-bit integer")
    })?;
    if length.fract() != 0.0
        || !(1.0..=4096.0).contains(&length)
        || address.checked_add(length as u64).is_none()
    {
        return Err(Exception::throw_range(
            ctx,
            "memory requires a valid range of 1–4096 bytes",
        ));
    }
    let mut bytes = vec![0; length as usize];
    let got = read(address, &mut bytes)?;
    let result = Object::new(ctx.clone())?;
    result.set("bytes", crate::modules::id_hex(&bytes[..got]))?;
    result.set("complete", got == bytes.len())?;
    let view: Object =
        constructor.construct((ArrayBuffer::new_copy(ctx.clone(), &bytes[..got])?,))?;
    result.set("view", view)?;
    Ok(result)
}

pub(super) fn page(
    ctx: &Ctx<'_>,
    options: Opt<Object<'_>>,
    deadline: Instant,
) -> rquickjs::Result<(usize, usize)> {
    check_deadline(ctx, deadline)?;
    let (offset, limit) = match options.0 {
        Some(options) => (
            options.get::<_, Option<u32>>("offset")?.unwrap_or(0),
            options.get::<_, Option<u32>>("limit")?.unwrap_or(128),
        ),
        None => (0, 128),
    };
    if offset > 200_000 || !(1..=256).contains(&limit) {
        return Err(Exception::throw_message(
            ctx,
            "expected offset in 0..=200000 and limit in 1..=256",
        ));
    }
    Ok((offset as usize, limit as usize))
}

pub(super) fn debugger_reply<'js>(
    ctx: &Ctx<'js>,
    result: Result<Json>,
) -> rquickjs::Result<Value<'js>> {
    match result {
        Ok(value) => as_js(ctx, value),
        Err(error) if error.is::<crate::Diagnostic>() => {
            let diagnostic = error.downcast::<crate::Diagnostic>().unwrap();
            as_js(
                ctx,
                json!({ "items": [], "next_offset": null, "issue": diagnostic, "warnings": [diagnostic] }),
            )
        }
        Err(error) => Err(Exception::throw_message(ctx, &error.to_string())),
    }
}

fn serialize<'js>(
    ctx: &Ctx<'js>,
    value: Value<'js>,
    replacer: &Function<'js>,
    limit: usize,
) -> rquickjs::Result<Json> {
    let text = ctx.json_stringify_replacer(value, replacer.clone())?;
    let Some(text) = text else {
        return Ok(Json::Null);
    };
    let text = text.to_string()?;
    if text.len() > limit {
        return Err(Exception::throw_message(
            ctx,
            "script output limit exceeded",
        ));
    }
    serde_json::from_str(&text).map_err(|error| Exception::throw_message(ctx, &error.to_string()))
}

fn push_output(
    ctx: &Ctx<'_>,
    entries: &RefCell<Vec<Json>>,
    bytes: &Cell<usize>,
    entry: Json,
) -> rquickjs::Result<()> {
    let count = bytes.get() + entry.to_string().len();
    let mut entries = entries.borrow_mut();
    if count > OUTPUT_LIMIT || entries.len() >= 1024 {
        return Err(Exception::throw_message(
            ctx,
            "script output limit exceeded",
        ));
    }
    bytes.set(count);
    entries.push(entry);
    Ok(())
}
