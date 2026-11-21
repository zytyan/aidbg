#[path = "aidbg-server/breakpoint_service.rs"]
mod breakpoint_service;

use aidbg::rpc::{
    BreakpointCapabilitiesRequest, BreakpointEventsRequest, CoreMode, CoredumpChunk,
    CoredumpRequest, DisassembleRequest, DocumentReply, FreezeMode, InstallBreakpointRequest,
    MAX_DOCUMENT, MAX_RPC, QuerySnapshotRequest, RemoveBreakpointRequest, ResolveAddressRequest,
    SearchSymbolsRequest, SnapshotReply, SnapshotRequest, SymbolMatch,
    coredump_chunk::Part,
    debugger_server::{Debugger, DebuggerServer},
};
use aidbg::{
    Result, Snapshot,
    selection::{Filter, with_id},
};
use breakpoint_service::Breakpoints;
use clap::Parser;
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status, transport::Server};

#[derive(Parser)]
#[command(about = "Run the local aidbg debugger service")]
struct Args {
    /// Absolute path in a private directory owned by this user.
    #[arg(long)]
    socket: PathBuf,
    /// Private directory for complete JSON snapshots.
    #[arg(long)]
    state_dir: PathBuf,
}

struct Store(PathBuf);

impl Store {
    fn save(&self, snapshot: Snapshot, filter: Filter) -> Result<SnapshotReply> {
        let mut file = tempfile::Builder::new()
            .prefix(".aidbg-")
            .rand_bytes(16)
            .tempfile_in(&self.0)?;
        let id = file
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(".aidbg-"))
            .ok_or_else(|| io::Error::other("invalid temporary snapshot ID"))?
            .to_owned();
        let mut doc = serde_json::to_value(snapshot)?;
        with_id(&mut doc, &id);
        let full = serde_json::to_vec(&doc)?;
        if full.len() > MAX_DOCUMENT {
            return Err(io::Error::other("snapshot exceeds the document size limit").into());
        }
        file.write_all(&full)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(self.0.join(format!("{id}.json")))?;
        Ok(SnapshotReply {
            snapshot_id: id,
            snapshot_json: serde_json::to_vec(&filter.apply(doc))?,
        })
    }

    fn query(&self, id: &str, filter: Filter) -> std::result::Result<SnapshotReply, Status> {
        if id.len() != 16 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(Status::invalid_argument("invalid snapshot ID"));
        }
        let file = File::open(self.0.join(format!("{id}.json"))).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Status::not_found("snapshot ID not found")
            } else {
                Status::internal(e.to_string())
            }
        })?;
        let mut bytes = Vec::new();
        file.take((MAX_DOCUMENT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(internal)?;
        if bytes.len() > MAX_DOCUMENT {
            return Err(Status::resource_exhausted(
                "saved snapshot exceeds the document size limit",
            ));
        }
        let doc = serde_json::from_slice(&bytes).map_err(internal)?;
        Ok(SnapshotReply {
            snapshot_id: id.into(),
            snapshot_json: serde_json::to_vec(&filter.apply(doc)).map_err(internal)?,
        })
    }
}

fn internal(e: impl ToString) -> Status {
    Status::internal(e.to_string())
}

struct Service {
    store: Arc<Store>,
    // The blocking job owns this guard until capture has finished cleanup.
    capture_lock: Arc<Mutex<()>>,
    coredumps: Arc<tokio::sync::Semaphore>,
    breakpoints: Breakpoints,
}

#[tonic::async_trait]
impl Debugger for Service {
    type CoredumpStream = ReceiverStream<std::result::Result<CoredumpChunk, Status>>;

    async fn coredump(
        &self,
        request: Request<CoredumpRequest>,
    ) -> std::result::Result<Response<Self::CoredumpStream>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let mode = CoreMode::try_from(req.mode)
            .map_err(|_| Status::invalid_argument("unknown coredump mode"))?;
        let timeout = req
            .timeout_ms
            .unwrap_or(aidbg::coredump::DEFAULT_TIMEOUT_MS);
        if timeout == 0 {
            return Err(Status::invalid_argument(
                "coredump timeout must be positive",
            ));
        }
        let options =
            aidbg::coredump::CaptureOptions::new(mode, timeout, req.buffer_mib, req.block_kib)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let lock = Arc::clone(&self.capture_lock);
        let slots = Arc::clone(&self.coredumps);
        let breakpoints = self.breakpoints.clone();
        let store = Arc::clone(&self.store);
        tokio::spawn(async move {
            let permit = tokio::select! {
                _ = sender.closed() => return,
                permit = slots.acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
            };
            let guard = tokio::select! {
                _ = sender.closed() => return,
                guard = lock.lock_owned() => guard,
            };
            let chunks = sender.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                if breakpoints.contains(req.pid) {
                    return Err(Status::failed_precondition(
                        "an active breakpoint session owns this PID",
                    ));
                }
                let dump = aidbg::coredump::prepare(
                    req.pid,
                    mode,
                    options,
                    &store.0,
                    &|| chunks.is_closed(),
                    || drop(guard),
                )
                .map_err(internal)?;
                let mut stream = io::Cursor::new(dump.header).chain(dump.payload);
                let mut buffer = vec![0; 256 * 1024];
                loop {
                    let n = stream.read(&mut buffer).map_err(internal)?;
                    if n == 0 {
                        break;
                    }
                    if chunks
                        .blocking_send(Ok(CoredumpChunk {
                            part: Some(Part::Data(buffer[..n].to_vec())),
                        }))
                        .is_err()
                    {
                        return Ok(());
                    }
                }
                let summary = serde_json::to_vec(&dump.summary).map_err(internal)?;
                let _ = chunks.blocking_send(Ok(CoredumpChunk {
                    part: Some(Part::SummaryJson(summary)),
                }));
                Ok(())
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let _ = sender.send(Err(error)).await;
                }
                Err(error) => {
                    let _ = sender.send(Err(internal(error))).await;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> std::result::Result<Response<SnapshotReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let mode = FreezeMode::try_from(req.freeze)
            .map_err(|_| Status::invalid_argument("unknown freeze mode"))?;
        let filter =
            Filter::parse(req.selection).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let store = Arc::clone(&self.store);
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        let result = tokio::task::spawn_blocking(move || {
            let snapshot = {
                let _guard = guard;
                if mode != FreezeMode::Never && breakpoints.contains(req.pid) {
                    return Err(Status::failed_precondition(
                        "an active breakpoint session owns this PID",
                    ));
                }
                Snapshot::run(req.pid, mode)
            };
            store.save(snapshot, filter).map_err(internal)
        })
        .await
        .map_err(internal)??;
        Ok(Response::new(result))
    }

    async fn query_snapshot(
        &self,
        request: Request<QuerySnapshotRequest>,
    ) -> std::result::Result<Response<SnapshotReply>, Status> {
        let req = request.into_inner();
        let filter =
            Filter::parse(req.selection).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let id = match req.event_id {
            Some(event) if req.snapshot_id.is_empty() => self.breakpoints.snapshot_id(event)?,
            None if !req.snapshot_id.is_empty() => req.snapshot_id,
            _ => {
                return Err(Status::invalid_argument(
                    "provide a snapshot ID or an event ID",
                ));
            }
        };
        let store = Arc::clone(&self.store);
        let reply = tokio::task::spawn_blocking(move || store.query(&id, filter))
            .await
            .map_err(internal)??;
        Ok(Response::new(reply))
    }

    async fn install_breakpoint(
        &self,
        request: Request<InstallBreakpointRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.install(req)?)
        })
        .await
        .map_err(internal)?
    }

    async fn remove_breakpoint(
        &self,
        request: Request<RemoveBreakpointRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.remove(req.pid, req.breakpoint_id)?)
        })
        .await
        .map_err(internal)?
    }

    async fn breakpoint_events(
        &self,
        request: Request<BreakpointEventsRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        document(self.breakpoints.events(request.into_inner()))
    }

    async fn search_symbols(
        &self,
        request: Request<SearchSymbolsRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let mode = SymbolMatch::try_from(req.match_mode)
            .map_err(|_| Status::invalid_argument("unknown symbol match mode"))?;
        tokio::task::spawn_blocking(move || {
            let result = aidbg::symbols::search(
                req.pid,
                &req.pattern,
                mode,
                req.module.as_deref(),
                req.limit.unwrap_or(256),
            )
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
            document(result)
        })
        .await
        .map_err(internal)?
    }

    async fn resolve_address(
        &self,
        request: Request<ResolveAddressRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        tokio::task::spawn_blocking(move || {
            let result = aidbg::symbols::resolve(req.pid, req.address)
                .map_err(|e| Status::failed_precondition(e.to_string()))?;
            document(result)
        })
        .await
        .map_err(internal)?
    }
    async fn disassemble(
        &self,
        request: Request<DisassembleRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        tokio::task::spawn_blocking(move || {
            let window = aidbg::disassembly::disassemble(
                req.pid,
                req.address,
                req.before.unwrap_or(4),
                req.after.unwrap_or(8),
                req.start,
            )
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
            document(window)
        })
        .await
        .map_err(internal)?
    }

    async fn breakpoint_capabilities(
        &self,
        _: Request<BreakpointCapabilitiesRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        document(aidbg::breakpoint::capabilities())
    }
}

fn validate_pid(pid: i32) -> std::result::Result<(), Status> {
    if pid <= 0 || pid as u32 == std::process::id() {
        return Err(Status::invalid_argument(
            "expected a positive PID other than the server PID",
        ));
    }
    Ok(())
}

fn document(value: impl serde::Serialize) -> std::result::Result<Response<DocumentReply>, Status> {
    let json = serde_json::to_vec(&value).map_err(internal)?;
    if json.len() > MAX_DOCUMENT {
        return Err(Status::resource_exhausted(
            "response exceeds the document size limit",
        ));
    }
    Ok(Response::new(DocumentReply { json }))
}

fn private_directory(path: &Path) -> Result<()> {
    let info = fs::metadata(path)?;
    let uid = unsafe { nix::libc::geteuid() };
    if !info.is_dir() || info.uid() != uid || info.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{} must be a private directory owned by this user (mode 0700)",
            path.display()
        ))
        .into());
    }
    Ok(())
}

struct Socket {
    path: PathBuf,
    identity: (u64, u64),
}
impl Drop for Socket {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path)
            && meta.file_type().is_socket()
            && (meta.dev(), meta.ino()) == self.identity
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.socket.is_absolute() {
        return Err(io::Error::other("use an absolute socket path").into());
    }
    private_directory(
        args.socket
            .parent()
            .ok_or_else(|| io::Error::other("socket parent is missing"))?,
    )?;
    private_directory(&args.state_dir)?;
    let listener = UnixListener::bind(&args.socket)?;
    let meta = fs::symlink_metadata(&args.socket)?;
    let socket = Socket {
        path: args.socket,
        identity: (meta.dev(), meta.ino()),
    };
    fs::set_permissions(&socket.path, Permissions::from_mode(0o600))?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let store = Arc::new(Store(args.state_dir));
    let (breakpoints, saver) = Breakpoints::new(Arc::clone(&store))?;
    let service = Service {
        store,
        breakpoints: breakpoints.clone(),
        capture_lock: Arc::new(Mutex::new(())),
        coredumps: Arc::new(tokio::sync::Semaphore::new(1)),
    };
    let result = Server::builder()
        .add_service(
            DebuggerServer::new(service)
                .max_decoding_message_size(MAX_RPC)
                .max_encoding_message_size(MAX_RPC),
        )
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async move {
            tokio::select! {
                _=tokio::signal::ctrl_c()=>{},
                _=term.recv()=>{},
            }
        })
        .await;
    tokio::task::spawn_blocking(move || {
        breakpoints.stop();
        if saver.join().is_err() {
            return Err(io::Error::other("event writer panicked"));
        }
        Ok(())
    })
    .await??;
    result?;
    Ok(())
}
