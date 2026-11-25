use aidbg::{
    Result,
    rpc::{
        debugger_server::{Debugger, DebuggerServer},
        *,
    },
    script::session::{Command, Worker},
};
use clap::Parser;
use std::{
    collections::BTreeMap,
    fs, io,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::net::{TcpListener, UnixListener};
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::{Request, Response, Status, transport::Server};

const LEASE: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 16;
type Reply = std::result::Result<Response<ToolReply>, Status>;

#[derive(Parser)]
#[command(version = aidbg::BUILD_VERSION)]
struct Args {
    #[arg(long, required_unless_present = "listen")]
    socket: Option<PathBuf>,
    #[arg(long)]
    listen: Option<SocketAddr>,
    #[arg(long)]
    state_dir: PathBuf,
}

struct Lease {
    renewed: Instant,
    worker: Option<Worker>,
}

struct Service {
    state_dir: PathBuf,
    sessions: Mutex<BTreeMap<String, Lease>>,
    profiler: Arc<tokio::sync::Semaphore>,
}

impl Service {
    fn lease<'a>(
        request: &Request<impl Sized>,
        sessions: &'a mut BTreeMap<String, Lease>,
    ) -> std::result::Result<&'a mut Lease, Status> {
        let token = request
            .metadata()
            .get("aidbg-session")
            .and_then(|value| value.to_str().ok())
            .filter(|token| {
                (24..=128).contains(&token.len())
                    && token
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
            .ok_or_else(|| Status::invalid_argument("a valid aidbg-session token is required"))?;
        sessions.retain(|_, lease| lease.renewed.elapsed() < LEASE);
        if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(token) {
            return Err(Status::resource_exhausted("too many debugger sessions"));
        }
        let now = Instant::now();
        let lease = sessions.entry(token.to_owned()).or_insert(Lease {
            renewed: now,
            worker: None,
        });
        lease.renewed = now;
        Ok(lease)
    }

    async fn command<T>(&self, request: Request<T>, command: impl FnOnce(T) -> Command) -> Reply {
        let receiver = {
            let mut sessions = self.sessions.lock().map_err(internal)?;
            let lease = Self::lease(&request, &mut sessions)?;
            let worker = match &mut lease.worker {
                Some(worker) => worker,
                slot => slot.insert(Worker::start(self.state_dir.clone()).map_err(internal)?),
            };
            worker
                .request(command(request.into_inner()))
                .map_err(internal)?
        };
        Ok(Response::new(receiver.await.map_err(internal)?))
    }
}

fn internal(err: impl std::fmt::Display) -> Status {
    Status::internal(err.to_string())
}

#[tonic::async_trait]
impl Debugger for Service {
    async fn heartbeat(&self, request: Request<HeartbeatRequest>) -> Reply {
        let mut sessions = self.sessions.lock().map_err(internal)?;
        Self::lease(&request, &mut sessions)?;
        Ok(Response::new(ToolReply::default()))
    }
    async fn run(&self, request: Request<RunProcessRequest>) -> Reply {
        self.command(request, Command::Run).await
    }
    async fn attach(&self, request: Request<AttachRequest>) -> Reply {
        self.command(request, |args| Command::Attach(args.pid))
            .await
    }
    async fn script_run(&self, request: Request<RunScriptRequest>) -> Reply {
        self.command(request, |args| {
            Command::Script(args.src, args.wait_ms, args.run)
        })
        .await
    }
    async fn script_wait(&self, request: Request<WaitScriptRequest>) -> Reply {
        self.command(request, |args| {
            Command::ScriptWait(args.script_id, args.wait_ms)
        })
        .await
    }
    async fn core_open(&self, request: Request<OpenCoreRequest>) -> Reply {
        self.command(request, Command::Core).await
    }
    async fn send_input(&self, request: Request<SendInputRequest>) -> Reply {
        self.command(request, |args| Command::Input(args.handler, Ok(args.data)))
            .await
    }
    async fn interrupt_input(&self, request: Request<InterruptInputRequest>) -> Reply {
        self.command(request, |args| {
            Command::Input(
                args.handler,
                Err(args.msg.unwrap_or_else(|| "input interrupted".into())),
            )
        })
        .await
    }
    async fn snapshot(&self, request: Request<SessionSnapshotRequest>) -> Reply {
        self.command(request, |args| Command::Snapshot(args.tid, args.context))
            .await
    }
    async fn ps(&self, request: Request<ProcessListRequest>) -> Reply {
        self.command(request, Command::Processes).await
    }
    async fn set_fork_policy(&self, request: Request<ForkPolicyRequest>) -> Reply {
        self.command(request, |args| Command::SetForkPolicy(args.mode))
            .await
    }
    async fn syscall_table(&self, request: Request<SyscallTableRequest>) -> Reply {
        self.command(request, |args| Command::SyscallTable(args.id, args.name))
            .await
    }
    async fn perf(&self, request: Request<SessionProfileRequest>) -> Reply {
        {
            let mut sessions = self.sessions.lock().map_err(internal)?;
            Self::lease(&request, &mut sessions)?;
        }
        let req = request.get_ref().to_owned();
        let result = if req.pid > 0 && req.stack != req.hotspot {
            let duration = req.duration_ms.unwrap_or(1000);
            let frequency = req.frequency_hz.unwrap_or(99);
            if !(10..=10_000).contains(&duration)
                || !(1..=1000).contains(&frequency)
                || req.tid.is_some_and(|tid| tid <= 0)
            {
                Err(io::Error::other(
                    "expected duration 10–10000 ms, frequency 1–1000 Hz and a positive TID",
                )
                .into())
            } else if let Ok(permit) = self.profiler.clone().try_acquire_owned() {
                let result = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    serde_json::to_value(aidbg::perf::run(
                        req.pid, req.stack, duration, frequency, req.tid,
                    )?)
                    .map_err(Into::into)
                })
                .await
                .map_err(internal)?;
                result
            } else {
                Err(io::Error::other("a perf collection is already running").into())
            }
        } else {
            Err(
                io::Error::other("select exactly one of hotspot or stack and a positive PID")
                    .into(),
            )
        };
        self.command(request, |_| Command::Result(result)).await
    }
}

struct Socket(PathBuf, u64, u64);
impl Drop for Socket {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.0)
            .is_ok_and(|meta| (meta.dev(), meta.ino()) == (self.1, self.2))
        {
            let _ = fs::remove_file(&self.0);
        }
    }
}

fn private_dir(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { nix::libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(
            io::Error::other("expected a directory owned by this user with mode 0700").into(),
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    private_dir(&args.state_dir)?;
    let tcp = match args.listen {
        Some(address) => Some(TcpListener::bind(address).await?),
        None => None,
    };
    let unix = args
        .socket
        .map(|path| -> Result<_> {
            if !path.is_absolute() {
                return Err(io::Error::other("use an absolute socket path").into());
            }
            private_dir(
                path.parent()
                    .ok_or_else(|| io::Error::other("socket has no parent"))?,
            )?;
            let listener = UnixListener::bind(&path)?;
            let meta = fs::symlink_metadata(&path)?;
            let socket = Socket(path, meta.dev(), meta.ino());
            fs::set_permissions(&socket.0, fs::Permissions::from_mode(0o600))?;
            Ok((listener, socket))
        })
        .transpose()?;

    let service = Arc::new(Service {
        state_dir: args.state_dir,
        sessions: Mutex::default(),
        profiler: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    let weak = Arc::downgrade(&service);
    let janitor = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        loop {
            interval.tick().await;
            let Some(service) = weak.upgrade() else { break };
            if let Ok(mut sessions) = service.sessions.lock() {
                sessions.retain(|_, lease| lease.renewed.elapsed() < LEASE);
            }
        }
    });
    let router = || {
        Server::builder().add_service(
            DebuggerServer::from_arc(service.clone())
                .max_decoding_message_size(MAX_RPC)
                .max_encoding_message_size(MAX_RPC),
        )
    };
    let (shutdown, signal) = tokio::sync::watch::channel(false);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let monitor = tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
        let _ = shutdown.send(true);
    });
    async fn wait(mut signal: tokio::sync::watch::Receiver<bool>) {
        let _ = signal.wait_for(|stop| *stop).await;
    }
    let unix_service = async {
        if let Some((listener, _socket)) = unix {
            router()
                .serve_with_incoming_shutdown(
                    UnixListenerStream::new(listener),
                    wait(signal.clone()),
                )
                .await?;
        }
        Ok::<_, tonic::transport::Error>(())
    };
    let tcp_service = async {
        if let Some(listener) = tcp {
            router()
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    wait(signal.clone()),
                )
                .await?;
        }
        Ok::<_, tonic::transport::Error>(())
    };
    let result = tokio::try_join!(unix_service, tcp_service);
    monitor.abort();
    janitor.abort();
    for lease in std::mem::take(
        &mut *service
            .sessions
            .lock()
            .map_err(|_| io::Error::other("session store poisoned"))?,
    )
    .into_values()
    {
        if let Some(worker) = lease.worker {
            worker.shutdown();
        }
    }
    result?;
    Ok(())
}
