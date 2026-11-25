use super::{CompactValue, extra_bytes, install};
use rquickjs::{CatchResultExt, Context, Ctx, Function, Object, Runtime, Value, class::JsCell};
use std::{cell::Cell, time::Instant};

fn setup(ctx: &Ctx<'_>) {
    let api: Object = ctx.eval(include_str!("../runtime.js")).catch(ctx).unwrap();
    install(ctx, &api).unwrap();
    let storage = Cell::new([7u8, 0, 0, 0]);
    let operation = Function::new(ctx.clone(), move |op: String, args: String| {
        let args: serde_json::Value = serde_json::from_str(&args).unwrap();
        match op.as_str() {
            "read" => {
                serde_json::to_string(&storage.get()[..args["length"].as_u64().unwrap() as usize])
                    .unwrap()
            }
            "write" => {
                storage.set(serde_json::from_value(args["bytes"].clone()).unwrap());
                "null".into()
            }
            _ => panic!("unexpected operation {op}"),
        }
    })
    .unwrap();
    let generation = Function::new(ctx.clone(), || 1).unwrap();
    api.get::<_, Function>("initialize")
        .unwrap()
        .call::<_, ()>((operation, crate::regs::ARCH, generation))
        .unwrap();
    eval(
        ctx,
        r#"
        globalThis.t = m.i32();
        globalThis.items = new Array(10000).fill(null);
        globalThis.addr = 0x100000000n;
        globalThis.v = t.at(addr, 13);
        globalThis.imm = t.value(7);
        globalThis.obj = m.struct({x:t}).at(addr, 13);
        globalThis.arr = m.array(t,16).at(addr, 13);
        globalThis.read = v.$read;
        globalThis.readImm = imm.$read;
        globalThis.write = v.$write;
        globalThis.writeImm = imm.$write;
    "#,
    );
}

fn rust_bytes(ctx: &Ctx<'_>) -> usize {
    // rquickjs 0.12.2 boxes a repr(C) ClassCell containing a vtable pointer and JsCell.
    #[repr(C)]
    struct CellLayout<T> {
        vtable: *const (),
        data: T,
    }
    let items: rquickjs::Array = ctx.globals().get("items").unwrap();
    let cell = size_of::<CellLayout<JsCell<'_, CompactValue<'_>>>>();
    items
        .iter::<Value>()
        .map(|value| cell + extra_bytes(&value.unwrap()))
        .sum()
}

fn eval(ctx: &Ctx<'_>, script: &str) {
    ctx.eval::<(), _>(script).catch(ctx).unwrap();
}

fn measure_memory(runtime: &Runtime, context: &Context, expression: &str) -> (f64, f64) {
    const COUNT: f64 = 10_000.0;
    context.with(|ctx| {
        eval(
            &ctx,
            &format!("{{ const i = 0; items[0] = {expression}; items[0] = null; }}"),
        )
    });
    runtime.run_gc();
    let before = runtime.memory_usage();
    let rust_bytes = context.with(|ctx| {
        eval(
            &ctx,
            &format!("for (let i=0;i<items.length;i++) items[i] = {expression};"),
        );
        rust_bytes(&ctx)
    });
    runtime.run_gc();
    let retained = runtime.memory_usage();
    context.with(|ctx| eval(&ctx, "items.fill(null);"));
    runtime.run_gc();
    let released = runtime.memory_usage();
    assert_eq!(
        released.obj_count, before.obj_count,
        "objects survived GC for {expression}"
    );
    (
        (retained.malloc_size - before.malloc_size) as f64 / COUNT,
        rust_bytes as f64 / COUNT,
    )
}

fn measure_time(runtime: &Runtime, context: &Context, expression: &str) -> f64 {
    const COUNT: u32 = 30_000;
    let mut samples = [0.; 7];
    context.with(|ctx| {
        let run: Function = ctx.eval(format!(
            "(n) => {{ let result; for (let i=0;i<n;i++) result = ({expression}); return result; }}"
        )).catch(&ctx).unwrap();
        let _: Value = run.call((COUNT / 10,)).catch(&ctx).unwrap();
        for sample in &mut samples {
            let start = Instant::now();
            let result: Value = run.call((COUNT,)).catch(&ctx).unwrap();
            *sample = start.elapsed().as_nanos() as f64 / f64::from(COUNT);
            std::hint::black_box(result);
        }
    });
    runtime.run_gc();
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

#[test]
fn native_value_memory_and_collection() {
    let runtime = Runtime::new().unwrap();
    let context = Context::full(&runtime).unwrap();
    context.with(|ctx| setup(&ctx));
    context.with(|ctx| {
        eval(
            &ctx,
            r#"
            const high = 0xffffffffffffffffn;
            if (t.at(high).$address() !== high) throw Error("u64 address was truncated");
            const child = obj.x;
            if (child.$parent !== obj || child.$tid !== 13) throw Error("parent or tid");
            obj.$tid = 21;
            if (child.$tid !== 21) throw Error("inherited tid");
            child.$tid = 8;
            if (child.$tid !== 8) throw Error("child tid");
            const read = child.$read;
            if (read !== child.$read || read() !== 7) throw Error("bound read");
            const bytes = imm.$readBytes();
            bytes[0] = 19;
            if (imm.$read() !== 7) throw Error("bytes alias");
            imm.$writeBytes(bytes);
            bytes[0] = 23;
            if (imm.$read() !== 19) throw Error("write bytes alias");
            obj.x = t.value(23);
            if (read() !== 23) throw Error("typed field assignment");
            arr[1] = t.value(7);
            if (read() !== 7) throw Error("typed index assignment");
        "#,
        )
    });
    for expression in [
        "t.at(addr + BigInt(i))",
        "t.value(7)",
        "obj.x",
        "arr[i & 15]",
    ] {
        let (js, rust) = measure_memory(&runtime, &context, expression);
        println!("{expression}: {js:.1} B QuickJS + {rust:.1} B Rust");
    }
}

#[test]
#[ignore = "microbenchmark"]
fn benchmark_native_value() {
    let runtime = Runtime::new().unwrap();
    let context = Context::full(&runtime).unwrap();
    context.with(|ctx| setup(&ctx));
    for (label, expression) in [
        ("address root", "t.at(addr + BigInt(i))"),
        ("immediate", "t.value(7)"),
        ("struct child", "obj.x"),
        ("array child", "arr[i & 15]"),
        (
            "root with cached read",
            "((v) => (v.$read, v))(t.at(addr + BigInt(i)))",
        ),
    ] {
        let (js, rust) = measure_memory(&runtime, &context, expression);
        println!("memory {label}: {js:.1} + {rust:.1} = {:.1} B", js + rust);
    }
    for (label, expression) in [
        ("create address root", "t.at(addr + BigInt(i))"),
        ("create immediate", "t.value(i)"),
        ("get type", "v.$type"),
        ("get size", "v.$size"),
        ("get cached read", "v.$read"),
        ("get address and call", "v.$address()"),
        ("struct field", "obj.x"),
        ("array index", "arr[i & 15]"),
        ("read field via Rust JSON bridge", "obj.x.$read()"),
        ("read via Rust JSON bridge", "read()"),
        ("write via Rust JSON bridge", "write(i)"),
        ("read immediate", "readImm()"),
        ("write immediate", "writeImm(i)"),
    ] {
        let time = measure_time(&runtime, &context, expression);
        println!("time {label}: {time:.0} ns/op");
    }
}
