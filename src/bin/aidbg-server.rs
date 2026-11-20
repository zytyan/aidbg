use aidbg::rpc::{
    FreezeMode, MAX_DOCUMENT, MAX_RPC, QuerySnapshotRequest, SnapshotReply, SnapshotRequest,
    debugger_server::{Debugger, DebuggerServer},
};
use aidbg::{
    Result, Snapshot,
    selection::{Filter, with_id},
};
use clap::Parser;
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status, transport::Server};

#[derive(Parser)]
#[command(about = "Run the local aidbg snapshot service")]
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
}

#[tonic::async_trait]
impl Debugger for Service {
    async fn snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> std::result::Result<Response<SnapshotReply>, Status> {
        let req = request.into_inner();
        if req.pid <= 0 || req.pid as u32 == std::process::id() {
            return Err(Status::invalid_argument(
                "expected a positive PID other than the server PID",
            ));
        }
        let mode = FreezeMode::try_from(req.freeze)
            .map_err(|_| Status::invalid_argument("unknown freeze mode"))?;
        let filter =
            Filter::parse(req.selection).map_err(|e| Status::invalid_argument(e.to_string()))?;
        let store = Arc::clone(&self.store);
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let result = tokio::task::spawn_blocking(move || {
            let snapshot = {
                let _guard = guard;
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
        let store = Arc::clone(&self.store);
        let reply = tokio::task::spawn_blocking(move || store.query(&req.snapshot_id, filter))
            .await
            .map_err(internal)??;
        Ok(Response::new(reply))
    }
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
    let service = Service {
        store: Arc::new(Store(args.state_dir)),
        capture_lock: Arc::new(Mutex::new(())),
    };
    Server::builder()
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
        .await?;
    Ok(())
}
