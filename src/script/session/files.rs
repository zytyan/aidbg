use rquickjs::{
    Ctx, Exception, Function, IntoJs, JsLifetime, Object, Promise, Runtime, TypedArray, Value,
    function::Opt,
    loader::{BuiltinLoader, BuiltinResolver, ImportAttributes, ModuleLoader, Resolver},
    module::{Declarations, Exports, ModuleDef},
};
use std::{
    cell::RefCell,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::mpsc::{self, Receiver, TryRecvError},
};

const NATIVE: &str = "aidbg:files";
const MODULES: [(&str, &str); 3] = [
    ("node:fs", include_str!("fs.js")),
    ("node:fs/promises", include_str!("fs_promises.js")),
    ("node:path", include_str!("path.js")),
];

pub(super) fn install(runtime: &Runtime) {
    let mut resolver = BuiltinResolver::default().with_module(NATIVE);
    let mut scripts = BuiltinLoader::default();
    for (name, source) in MODULES {
        resolver.add_module(name);
        scripts.add_module(name, source);
    }
    runtime.set_loader(
        SessionResolver(resolver),
        (ModuleLoader::default().with_module(NATIVE, Files), scripts),
    );
}

struct SessionResolver(BuiltinResolver);

impl Resolver for SessionResolver {
    fn resolve<'js>(
        &mut self,
        ctx: &Ctx<'js>,
        base: &str,
        name: &str,
        attributes: Option<ImportAttributes<'js>>,
    ) -> rquickjs::Result<String> {
        if name == NATIVE && !MODULES.iter().any(|(module, _)| *module == base) {
            return Err(rquickjs::Error::new_resolving(base, name));
        }
        self.0.resolve(ctx, base, name, attributes)
    }
}

struct Files;

enum Output {
    Bytes(Vec<u8>),
    Text(String),
    Entries(Vec<String>),
    Stat(fs::Metadata),
    Exists(bool),
    Unit,
}

impl<'js> IntoJs<'js> for Output {
    fn into_js(self, ctx: &Ctx<'js>) -> rquickjs::Result<Value<'js>> {
        match self {
            Self::Bytes(bytes) => TypedArray::<u8>::new(ctx.clone(), bytes)?.into_js(ctx),
            Self::Text(text) => text.into_js(ctx),
            Self::Entries(entries) => entries.into_js(ctx),
            Self::Exists(exists) => exists.into_js(ctx),
            Self::Unit => ().into_js(ctx),
            Self::Stat(metadata) => {
                let result = Object::new(ctx.clone())?;
                result.set("size", metadata.len() as f64)?;
                result.set("file", metadata.is_file())?;
                result.set("directory", metadata.is_dir())?;
                result.into_js(ctx)
            }
        }
    }
}

fn read_file(path: &str) -> io::Result<Vec<u8>> {
    // FIFOs and device nodes must not block the session worker.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("expected a regular file"));
    }
    let mut bytes = Vec::new();
    const LIMIT: u64 = 16 * 1024 * 1024;
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::other("file exceeds 16 MiB"));
    }
    Ok(bytes)
}

fn operate(op: &str, path: &str, option: Option<i32>) -> io::Result<Output> {
    Ok(match op {
        "read" => {
            let bytes = read_file(path)?;
            if option == Some(1) {
                Output::Text(String::from_utf8_lossy(&bytes).into_owned())
            } else {
                Output::Bytes(bytes)
            }
        }
        "readdir" => Output::Entries(
            fs::read_dir(path)?
                .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
                .collect::<io::Result<_>>()?,
        ),
        "stat" => Output::Stat(fs::metadata(path)?),
        "access" => {
            let mode =
                nix::unistd::AccessFlags::from_bits(option.unwrap_or(0)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid access mode")
                })?;
            nix::unistd::access(Path::new(path), mode).map_err(io::Error::from)?;
            Output::Unit
        }
        "exists" => Output::Exists(Path::new(path).exists()),
        "realpath" => Output::Text(fs::canonicalize(path)?.to_string_lossy().into_owned()),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown filesystem operation",
            ));
        }
    })
}

struct Pending<'js> {
    receiver: Receiver<io::Result<Output>>,
    resolve: Function<'js>,
    reject: Function<'js>,
}

#[derive(Default)]
pub(super) struct Jobs<'js>(RefCell<Vec<Pending<'js>>>);

// The only JavaScript references are the promise callbacks in Pending.
unsafe impl<'js> JsLifetime<'js> for Jobs<'js> {
    type Changed<'to> = Jobs<'to>;
}

pub(super) fn poll(ctx: &Ctx<'_>) -> rquickjs::Result<()> {
    let jobs = ctx.userdata::<Jobs>().expect("filesystem jobs installed");
    // Release the borrow before calling JS promise functions.
    let mut ready = Vec::new();
    jobs.0.borrow_mut().retain_mut(|job| {
        let result = match job.receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return true,
            Err(TryRecvError::Disconnected) => Err(io::Error::other("filesystem worker exited")),
        };
        ready.push((result, job.resolve.clone(), job.reject.clone()));
        false
    });
    drop(jobs);
    for (result, resolve, reject) in ready {
        match result {
            Ok(value) => resolve.call::<_, ()>((value,))?,
            Err(err) => {
                reject.call::<_, ()>((Exception::from_message(ctx.clone(), &err.to_string())?,))?
            }
        }
    }
    Ok(())
}

impl ModuleDef for Files {
    fn declare<'js>(decl: &Declarations<'js>) -> rquickjs::Result<()> {
        decl.declare("sync")?
            .declare("asyncOperation")?
            .declare("cwd")?;
        Ok(())
    }

    fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> rquickjs::Result<()> {
        exports.export(
            "sync",
            Function::new(
                ctx.clone(),
                |ctx: Ctx<'js>, op: String, path: String, Opt(option): Opt<i32>| {
                    operate(&op, &path, option)
                        .map_err(|err| Exception::throw_message(&ctx, &err.to_string()))
                },
            )?,
        )?;
        exports.export(
            "asyncOperation",
            Function::new(
                ctx.clone(),
                |ctx: Ctx<'js>, op: String, path: String, Opt(option): Opt<i32>| {
                    let jobs = ctx.userdata::<Jobs>().expect("filesystem jobs installed");
                    let mut jobs = jobs.0.borrow_mut();
                    if jobs.len() >= 16 {
                        return Err(Exception::throw_range(
                            &ctx,
                            "too many pending filesystem operations",
                        ));
                    }
                    let (promise, resolve, reject) = Promise::new(&ctx)?;
                    let (send, receiver) = mpsc::sync_channel(1);
                    std::thread::Builder::new()
                        .name("aidbg-fs".into())
                        .spawn(move || {
                            let _ = send.send(operate(&op, &path, option));
                        })
                        .map_err(|err| Exception::throw_message(&ctx, &err.to_string()))?;
                    jobs.push(Pending {
                        receiver,
                        resolve,
                        reject,
                    });
                    Ok(promise)
                },
            )?,
        )?;
        exports.export(
            "cwd",
            Function::new(ctx.clone(), |ctx: Ctx<'js>| {
                std::env::current_dir()
                    .map(|path| path.to_string_lossy().into_owned())
                    .map_err(|err| Exception::throw_message(&ctx, &err.to_string()))
            })?,
        )?;
        Ok(())
    }
}
