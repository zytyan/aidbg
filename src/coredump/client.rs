use aidbg::Result;
#[cfg(unix)]
use aidbg::coredump::try_lock;
use aidbg::coredump::{hash_reader, valid_dump_id};
use aidbg::rpc::{
    Client, CoreMode, CoredumpJob, CoredumpJobState, CoredumpRequest, DownloadCoredumpRequest,
    GetCoredumpRequest, StartCoredumpRequest, coredump_chunk::Part,
};
use clap::{Args, ValueEnum};
#[cfg(unix)]
use nix::libc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Seek, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tonic::{Code, Request, Status};

pub(super) async fn upload_file(
    mut client: Client,
    path: &Path,
    kind: aidbg::rpc::artifact_header::Kind,
) -> Result<Value> {
    use aidbg::rpc::{ArtifactChunk, ArtifactHeader, artifact_chunk::Part};
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(io::Error::other("artifact must be a regular file").into());
    }
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let task = tokio::spawn(async move {
        let send = async |part| sender.send(ArtifactChunk { part: Some(part) }).await;
        if send(Part::Header(ArtifactHeader {
            kind: kind as i32,
            size: metadata.len(),
        }))
        .await
        .is_err()
        {
            return Ok::<_, io::Error>(());
        }
        let mut buffer = vec![0; 256 * 1024];
        loop {
            let count = file.read(&mut buffer).await?;
            if count == 0 || send(Part::Data(buffer[..count].to_vec())).await.is_err() {
                return Ok(());
            }
        }
    });
    let reply = client
        .upload_artifact(Request::new(tokio_stream::wrappers::ReceiverStream::new(
            receiver,
        )))
        .await;
    task.await??;
    Ok(serde_json::from_slice(&reply?.into_inner().json)?)
}

#[derive(Args, Deserialize, JsonSchema)]
pub(super) struct RetainArgs {
    #[arg(long)]
    dump_id: String,
    #[arg(long)]
    retention_secs: u64,
}

pub(super) async fn retain_core(mut client: Client, args: RetainArgs) -> Result<Value> {
    let result = client
        .retain_coredump(Request::new(aidbg::rpc::RetainCoredumpRequest {
            dump_id: args.dump_id,
            retention_secs: args.retention_secs,
        }))
        .await?
        .into_inner();
    Ok(
        serde_json::json!({"dump_id": result.dump_id, "expires_unix_secs": result.expires_unix_secs}),
    )
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum DumpMode {
    Lite,
    #[serde(rename = "stack-4k", alias = "lite-stack")]
    #[value(name = "stack-4k", alias = "lite-stack")]
    Stack4k,
    #[default]
    Stack,
    Standard,
    #[serde(alias = "extend")]
    #[value(alias = "extend")]
    Extended,
    Full,
}

impl From<DumpMode> for CoreMode {
    fn from(mode: DumpMode) -> Self {
        match mode {
            DumpMode::Lite => Self::CoreLite,
            DumpMode::Stack4k => Self::CoreStack4k,
            DumpMode::Stack => Self::CoreStack,
            DumpMode::Standard => Self::CoreStandard,
            DumpMode::Extended => Self::CoreExtended,
            DumpMode::Full => Self::CoreFull,
        }
    }
}

#[derive(Args, Deserialize, JsonSchema)]
pub(super) struct CoredumpArgs {
    #[arg(long, required_unless_present_any = ["resume", "dump_id", "run_id"], conflicts_with_all = ["resume", "dump_id", "run_id"])]
    pid: Option<i32>,
    /// Capture the process controlled by this run.
    #[arg(long, conflicts_with_all = ["resume", "dump_id"])]
    run_id: Option<String>,
    /// Download an existing retained core, including one saved by a signal callback.
    #[arg(long, conflicts_with = "resume")]
    dump_id: Option<String>,
    /// Memory coverage of the dump (default: stack).
    #[arg(long, value_enum)]
    mode: Option<DumpMode>,
    /// New client-side .core.zst path, or the same path when resuming.
    #[arg(long)]
    output: PathBuf,
    /// Continue downloading the saved coredump for this output path.
    #[arg(long)]
    #[serde(default)]
    resume: bool,
    /// Time budget for capturing the target, in milliseconds.
    #[arg(long)]
    timeout_ms: Option<u32>,
    /// Server capture-buffer budget in MiB. Zero uses file staging.
    #[arg(long)]
    buffer_mib: Option<u32>,
    /// Server memory-read block size in KiB.
    #[arg(long)]
    block_kib: Option<u32>,
    /// Time limit for a stalled RPC or download chunk, in milliseconds (default: 30000).
    #[arg(long)]
    download_idle_ms: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    dump_id: String,
}

struct LocalDump {
    output: PathBuf,
    partial: PathBuf,
    checkpoint: PathBuf,
    id: String,
    file: File,
    _lock: File,
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_owned();
    path.push(suffix);
    path.into()
}

fn require_new(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn check_private(file: &File) -> io::Result<()> {
    let info = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !info.is_file() || info.uid() != uid || info.mode() & 0o077 != 0 || info.nlink() != 1 {
        return Err(io::Error::other(
            "coredump progress must be a private regular file owned by this user",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn check_private(file: &File) -> io::Result<()> {
    const REPARSE_POINT: u32 = 0x400;
    let info = file.metadata()?;
    if !info.is_file() || info.file_attributes() & REPARSE_POINT != 0 {
        return Err(io::Error::other("coredump progress must be a regular file"));
    }
    Ok(())
}

#[cfg(windows)]
fn try_lock(file: &File) -> io::Result<()> {
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::Error(error) => error,
        std::fs::TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
    })
}

fn progress_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    options
}

impl LocalDump {
    fn open(output: PathBuf, resume: bool, saved_id: Option<String>) -> Result<Self> {
        require_new(&output)?;
        let partial = with_suffix(&output, ".part");
        let checkpoint = with_suffix(&output, ".part.json");
        let (id, file, lock) = if resume {
            let mut lock = progress_options().open(&checkpoint)?;
            check_private(&lock)?;
            try_lock(&lock)
                .map_err(|_| io::Error::other("another client owns this coredump output"))?;
            require_new(&output)?;
            let mut data = Vec::new();
            (&mut lock).take(4096).read_to_end(&mut data)?;
            let Checkpoint { dump_id } = serde_json::from_slice(&data)?;
            if !valid_dump_id(&dump_id) {
                return Err(io::Error::other("invalid coredump checkpoint ID").into());
            }
            let file = progress_options()
                .create(true)
                .truncate(false)
                .open(&partial)?;
            check_private(&file)?;
            (dump_id, file, lock)
        } else {
            require_new(&partial)?;
            require_new(&checkpoint)?;
            let parent = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut lock = tempfile::Builder::new()
                .prefix(".aidbg-")
                .rand_bytes(32)
                .tempfile_in(parent)?;
            try_lock(lock.as_file())?;
            let id = lock
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix(".aidbg-"))
                .filter(|id| valid_dump_id(id))
                .ok_or_else(|| io::Error::other("could not generate coredump ID"))?
                .to_owned();
            let id = saved_id.unwrap_or(id);
            serde_json::to_writer(
                &mut lock,
                &Checkpoint {
                    dump_id: id.clone(),
                },
            )?;
            lock.as_file().sync_all()?;
            let lock = lock.persist_noclobber(&checkpoint)?;
            let file = match progress_options().create_new(true).open(&partial) {
                Ok(file) => file,
                Err(error) => {
                    let _ = fs::remove_file(&checkpoint);
                    return Err(error.into());
                }
            };
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            (id, file, lock)
        };
        Ok(Self {
            output,
            partial,
            checkpoint,
            id,
            file,
            _lock: lock,
        })
    }

    fn discard_progress(&self) {
        let _ = fs::remove_file(&self.partial);
        let _ = fs::remove_file(&self.checkpoint);
    }

    fn publish(&self) -> io::Result<()> {
        let mut path = tempfile::TempPath::try_from_path(self.partial.clone())?;
        path.disable_cleanup(true);
        path.persist_noclobber(&self.output)
            .map_err(|error| error.error)?;
        let _ = fs::remove_file(&self.checkpoint);
        Ok(())
    }
}

async fn rpc<T>(
    idle: Duration,
    request: impl Future<Output = std::result::Result<T, Status>>,
) -> std::result::Result<T, Status> {
    tokio::time::timeout(idle, request)
        .await
        .map_err(|_| Status::deadline_exceeded("coredump connection or download stalled"))?
}

fn request(args: &CoredumpArgs) -> Result<Option<CoredumpRequest>> {
    if args.resume || args.dump_id.is_some() {
        if let Some(id) = args.dump_id.as_deref()
            && (args.resume || !valid_dump_id(id))
        {
            return Err(
                io::Error::other("invalid retained dump ID or conflicting resume request").into(),
            );
        }
        if args.pid.is_some()
            || args.run_id.is_some()
            || args.mode.is_some()
            || args.timeout_ms.is_some()
            || args.buffer_mib.is_some()
            || args.block_kib.is_some()
        {
            return Err(io::Error::other(
                "saved coredump downloads take the original capture settings",
            )
            .into());
        }
        return Ok(None);
    }
    let pid = match (args.pid, args.run_id.as_deref()) {
        (Some(pid), None) if pid > 0 => pid,
        (None, Some(id)) if !id.is_empty() => 0,
        _ => {
            return Err(aidbg::Diagnostic::new(
                "INVALID_ARGUMENT",
                "Specify exactly one positive pid or a run_id",
                None,
            )
            .into());
        }
    };
    let mode = CoreMode::from(args.mode.unwrap_or_default());
    let timeout = args
        .timeout_ms
        .unwrap_or(aidbg::coredump::DEFAULT_TIMEOUT_MS);
    if timeout == 0 {
        return Err(io::Error::other("coredump timeout must be positive").into());
    }
    aidbg::coredump::CaptureOptions::new(mode, timeout, args.buffer_mib, args.block_kib)?;
    Ok(Some(CoredumpRequest {
        pid,
        mode: mode as i32,
        timeout_ms: args.timeout_ms,
        buffer_mib: args.buffer_mib,
        block_kib: args.block_kib,
        run_id: args.run_id.clone(),
    }))
}

async fn ready_job(
    client: &mut Client,
    local: &LocalDump,
    capture: Option<CoredumpRequest>,
    idle: Duration,
) -> Result<CoredumpJob> {
    let get = GetCoredumpRequest {
        dump_id: local.id.clone(),
    };
    let mut job = if let Some(capture) = capture {
        match rpc(
            idle,
            client.start_coredump(Request::new(StartCoredumpRequest {
                dump_id: local.id.clone(),
                capture: Some(capture),
            })),
        )
        .await
        {
            Ok(response) => response.into_inner(),
            Err(error) => {
                if matches!(
                    error.code(),
                    Code::InvalidArgument | Code::AlreadyExists | Code::ResourceExhausted
                ) {
                    local.discard_progress();
                }
                return Err(error.into());
            }
        }
    } else {
        rpc(idle, client.get_coredump(Request::new(get.clone())))
            .await?
            .into_inner()
    };
    let mut poll_delay = Duration::from_millis(10);
    loop {
        if job.dump_id != local.id {
            return Err(io::Error::other("coredump response has a different ID").into());
        }
        match CoredumpJobState::try_from(job.state)? {
            CoredumpJobState::CoredumpReady => return Ok(job),
            CoredumpJobState::CoredumpFailed => {
                local.discard_progress();
                return Err(io::Error::other(job.error).into());
            }
            CoredumpJobState::CoredumpPending => {
                tokio::time::sleep(poll_delay).await;
                poll_delay = (poll_delay * 2).min(Duration::from_millis(200));
                job = rpc(idle, client.get_coredump(Request::new(get.clone())))
                    .await?
                    .into_inner();
            }
        }
    }
}

async fn download(
    client: &mut Client,
    local: &mut LocalDump,
    job: CoredumpJob,
    idle: Duration,
) -> Result<Value> {
    let mut summary = serde_json::from_slice::<Value>(&job.summary_json)?;
    let size = job.compressed_bytes;
    if size == 0
        || summary["compressed_bytes"].as_u64() != Some(size)
        || !matches!(
            summary["status"].as_str(),
            Some("complete" | "complete_without_vvar" | "partial")
        )
        || job.sha256.len() != 32
    {
        return Err(io::Error::other("invalid saved coredump metadata").into());
    }

    let offset = local.file.seek(io::SeekFrom::End(0))?;
    if offset > size {
        return Err(io::Error::other("partial file is larger than the saved coredump").into());
    }
    let mut received = offset;
    if received < size {
        let mut stream = rpc(
            idle,
            client.download_coredump(Request::new(DownloadCoredumpRequest {
                dump_id: local.id.clone(),
                offset,
            })),
        )
        .await?
        .into_inner();
        while let Some(chunk) = rpc(idle, stream.message()).await? {
            let Some(Part::Data(data)) = chunk.part else {
                return Err(io::Error::other("unexpected coredump download chunk").into());
            };
            if data.is_empty() || data.len() as u64 > size - received {
                return Err(io::Error::other("invalid coredump download chunk size").into());
            }
            // A bounded synchronous write cannot outlive cancellation and
            // race another client that acquires the checkpoint lock.
            local.file.write_all(&data)?;
            received += data.len() as u64;
        }
    }
    if received != size {
        return Err(io::Error::other("coredump transfer ended before all bytes arrived").into());
    }

    let mut file = local.file.try_clone()?;
    let hash = tokio::task::spawn_blocking(move || -> io::Result<[u8; 32]> {
        file.sync_all()?;
        file.rewind()?;
        let mut hash = Sha256::new();
        hash_reader(file, &mut hash)?;
        Ok(hash.finalize().into())
    })
    .await??;
    if hash.as_slice() != job.sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "coredump SHA-256 mismatch. Remove {} before retrying --resume to download the saved core from the beginning",
                local.partial.display()
            ),
        ).into());
    }
    local.publish()?;
    summary["path"] = Value::String(local.output.to_string_lossy().into_owned());
    summary["output_host"] = "client".into();
    summary["dump_id"] = Value::String(local.id.clone());
    summary["sha256"] = Value::String(hash.iter().map(|byte| format!("{byte:02x}")).collect());
    summary["resumed_from"] = Value::from(offset);
    summary["expires_unix_secs"] = Value::from(job.expires_unix_secs);
    Ok(summary)
}

pub(super) async fn save_coredump(mut client: Client, args: CoredumpArgs) -> Result<Value> {
    let capture = request(&args)?;
    let idle = Duration::from_millis(args.download_idle_ms.unwrap_or(30_000).into());
    if idle.is_zero() {
        return Err(io::Error::other("download idle timeout must be positive").into());
    }
    let mut local = LocalDump::open(args.output, args.resume, args.dump_id)?;
    let result = async {
        let job = ready_job(&mut client, &local, capture, idle).await?;
        download(&mut client, &mut local, job, idle).await
    }
    .await;
    result.map_err(|error| {
        if local.checkpoint.exists()
            && !error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::InvalidData)
            && !error
                .downcast_ref::<Status>()
                .is_some_and(|e| e.code() == Code::NotFound)
        {
            io::Error::other(format!(
                "{error}. Coredump {}; use --resume with the same --output to retry",
                local.id
            ))
            .into()
        } else {
            error
        }
    })
}

#[derive(Args, Deserialize, JsonSchema)]
pub(super) struct BundleArgs {
    #[arg(long)]
    dump_id: String,
    /// New directory on the client to receive the bundle.
    #[arg(long)]
    output: PathBuf,
    /// Match an alternate executable on the server.
    #[arg(long)]
    executable: Option<PathBuf>,
    #[arg(long)]
    debug_symbols: Option<PathBuf>,
    #[arg(skip)]
    script_source: Option<String>,
    /// TypeScript source file to include in the bundle.
    #[arg(long)]
    #[serde(skip)]
    script_file: Option<PathBuf>,
    #[arg(skip)]
    script_output: Option<Value>,
    #[arg(long)]
    conclusion: Option<String>,
    /// Explicit environment notes for reproduction.
    #[arg(skip)]
    environment: Option<Value>,
}

pub(super) async fn export_bundle(mut client: Client, args: BundleArgs) -> Result<Value> {
    require_new(&args.output)?;
    if !valid_dump_id(&args.dump_id) {
        return Err(io::Error::other("invalid retained dump ID").into());
    }
    let parent = args
        .output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::tempdir_in(parent)?;
    #[cfg(unix)]
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
    let idle = Duration::from_secs(30);
    let dump_path = staging.path().join("target.core.zst");
    let mut core = save_coredump(
        client.clone(),
        CoredumpArgs {
            run_id: None,
            pid: None,
            dump_id: Some(args.dump_id.clone()),
            output: dump_path,
            mode: None,
            resume: false,
            timeout_ms: None,
            buffer_mib: None,
            block_kib: None,
            download_idle_ms: None,
        },
    )
    .await?;
    core["path"] = Value::from("target.core.zst");

    let request = aidbg::script::CoreImagesRequest {
        dump_id: args.dump_id,
        symbols: aidbg::script::CoreSymbols {
            executable: args.executable,
            debug_symbols: args.debug_symbols,
        },
    };
    let mut images = rpc(
        idle,
        client.download_core_images(Request::new(aidbg::rpc::ScriptDocumentRequest {
            json: serde_json::to_vec(&request)?,
        })),
    )
    .await?
    .into_inner();
    let mut files = vec!["target.core.zst".to_owned()];
    let mut executable_info = Value::Null;
    let mut server_version = Value::Null;
    let mut architecture = Value::Null;
    let mut entries = Vec::new();
    while let Some(chunk) = rpc(idle, images.message()).await? {
        let Some(Part::SummaryJson(header)) = chunk.part else {
            return Err(io::Error::other("expected bundle file metadata").into());
        };
        let info: Value = serde_json::from_slice(&header)?;
        let name = info["name"]
            .as_str()
            .filter(|name| matches!(*name, "executable" | "executable.debug"))
            .ok_or_else(|| io::Error::other("unexpected bundle file name"))?;
        if files.iter().any(|file| file == name) {
            return Err(io::Error::other("duplicate bundle file").into());
        }
        let size = info["size"]
            .as_u64()
            .filter(|size| (1..=128 * 1024 * 1024).contains(size))
            .ok_or_else(|| io::Error::other("invalid bundle file size"))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(staging.path().join(name))?;
        let mut hash = Sha256::new();
        let mut remaining = size;
        while remaining > 0 {
            let Some(Part::Data(data)) = rpc(idle, images.message())
                .await?
                .and_then(|chunk| chunk.part)
            else {
                return Err(io::Error::other("bundle file transfer ended prematurely").into());
            };
            if data.is_empty() || data.len() as u64 > remaining {
                return Err(io::Error::other("invalid bundle file chunk size").into());
            }
            file.write_all(&data)?;
            hash.update(&data);
            remaining -= data.len() as u64;
        }
        file.sync_all()?;
        #[cfg(unix)]
        if name == "executable" {
            file.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        files.push(name.to_owned());
        entries.push(serde_json::json!({
            "path": name, "size": size,
            "sha256": hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        }));
        executable_info = info["executable"].clone();
        architecture = info["architecture"].clone();
        server_version = info["server_version"].clone();
    }
    if !files.iter().any(|file| file == "executable") {
        return Err(io::Error::other("bundle is missing its verified executable").into());
    }

    if let Some(replay) = core
        .as_object_mut()
        .and_then(|core| core.remove("breakpoint_replay"))
    {
        let sources = replay["rules"]
            .as_object()
            .ok_or_else(|| io::Error::other("invalid breakpoint rule metadata"))?;
        fs::create_dir(staging.path().join("rules"))?;
        for (key, source) in sources {
            let source = source
                .as_str()
                .ok_or_else(|| io::Error::other("invalid rule source"))?;
            let name = rule_path(key)?;
            fs::write(staging.path().join(&name), source)?;
            entries.push(serde_json::json!({"path": name, "size": source.len(), "sha256": Sha256::digest(source.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>()}));
        }
        let points = serde_json::to_vec_pretty(&replay["breakpoints"])?;
        fs::write(staging.path().join("breakpoints.json"), &points)?;
        entries.push(serde_json::json!({"path": "breakpoints.json", "size": points.len(), "sha256": Sha256::digest(&points).iter().map(|byte| format!("{byte:02x}")).collect::<String>()}));
        files.extend(["rules".into(), "breakpoints.json".into()]);
    }

    let source = match args.script_file {
        Some(path) => Some(super::script_client::read_source(&path)?),
        None => args.script_source,
    };
    if let Some(source) = source {
        if source.len() > 64 * 1024 {
            return Err(io::Error::other("script source exceeds 64 KiB").into());
        }
        fs::write(staging.path().join("analysis.ts"), source)?;
        files.push("analysis.ts".into());
    }
    let manifest = serde_json::json!({
        "version": 1,
        "core": core,
        "executable": executable_info,
        "files": entries,
        "script": files.iter().any(|name| name == "analysis.ts").then_some("analysis.ts"),
        "script_output": args.script_output,
        "conclusion": args.conclusion,
        "environment": args.environment,
        "client_version": aidbg::BUILD_VERSION,
        "server_version": server_version,
        "architecture": architecture,
        "replay": {
            "core": "target.core.zst", "executable": "executable",
            "debug_symbols": files.iter().any(|name| name == "executable.debug").then_some("executable.debug"),
            "breakpoints": files.iter().any(|name| name == "breakpoints.json").then_some("breakpoints.json"),
        },
    });
    fs::write(
        staging.path().join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    files.push("manifest.json".into());

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&args.output)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&args.output)?;
    for (index, name) in files.iter().enumerate() {
        if let Err(error) = fs::rename(staging.path().join(name), args.output.join(name)) {
            for published in &files[..index] {
                if published == "rules" {
                    let _ = fs::remove_dir_all(args.output.join(published));
                } else {
                    let _ = fs::remove_file(args.output.join(published));
                }
            }
            let _ = fs::remove_dir(&args.output);
            return Err(error.into());
        }
    }
    Ok(serde_json::json!({
        "status": "complete", "path": args.output,
        "manifest": args.output.join("manifest.json"), "warnings": core["warnings"],
    }))
}

fn rule_path(key: &str) -> Result<PathBuf> {
    if key.is_empty()
        || key.len() > 48
        || !key.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    {
        return Err(io::Error::other("invalid bundle rule ID").into());
    }
    Ok(PathBuf::from("rules").join(format!("{key}.ts")))
}

#[derive(Args, Deserialize, JsonSchema)]
pub(super) struct RestoreArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long, required_unless_present = "launch", conflicts_with = "launch")]
    run_id: Option<String>,
    /// Upload and launch the bundled executable on the server, paused at entry.
    #[arg(long)]
    #[serde(default)]
    launch: bool,
}

#[derive(Deserialize)]
struct ReplayPoint {
    breakpoint_id: u64,
    kind: String,
    scope: String,
    module: Option<ReplayModule>,
    module_offset: Option<String>,
    length: Option<u32>,
    timeout_ms: u32,
    #[serde(default)]
    stop_after_hit: bool,
    thread: Option<String>,
    source: Option<String>,
    export: Option<String>,
    live: Option<ReplayInstall>,
}

#[derive(Deserialize)]
struct ReplayInstall {
    ordinal: usize,
    requested_address: String,
}

#[derive(Deserialize)]
struct ReplayModule {
    path: String,
    build_id: Option<String>,
}

pub(super) async fn restore_breakpoints(mut client: Client, args: RestoreArgs) -> Result<Value> {
    use aidbg::rpc::ScriptDocumentRequest;
    let mut launched_path = None;
    let id = match (args.run_id, args.launch) {
        (Some(id), false) => id,
        (None, true) => {
            let executable = args.bundle.join("executable");
            if !fs::symlink_metadata(&executable)?.is_file() {
                return Err(io::Error::other("expected a regular bundled executable").into());
            }
            let uploaded = upload_file(
                client.clone(),
                &executable,
                aidbg::rpc::artifact_header::Kind::Executable,
            )
            .await?;
            let path = uploaded["server_path"]
                .as_str()
                .ok_or_else(|| io::Error::other("upload did not return an executable path"))?;
            let reply = client
                .run_target(Request::new(ScriptDocumentRequest {
                    json: serde_json::to_vec(
                        &serde_json::json!({"executable": path, "pause_at_entry": true}),
                    )?,
                }))
                .await?
                .into_inner();
            let run: Value = serde_json::from_slice(&reply.json)?;
            let id = run["run_id"]
                .as_str()
                .ok_or_else(|| io::Error::other("server did not return a run ID"))?;
            launched_path = Some(path.to_owned());
            id.to_owned()
        }
        _ => return Err(io::Error::other("provide run_id or launch=true").into()),
    };
    let result = restore_into(&mut client, &args.bundle, &id, launched_path.as_deref()).await;
    if result.is_err() && launched_path.is_some() {
        client
            .run_cancel(Request::new(ScriptDocumentRequest {
                json: serde_json::to_vec(&serde_json::json!({"run_id": id}))?,
            }))
            .await?;
    }
    let mut result = result?;
    result["run_id"] = id.into();
    Ok(result)
}

fn read_bundle_metadata(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("expected a regular bundle metadata file").into());
    }
    let mut content = Vec::new();
    File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut content)?;
    if content.len() > 1024 * 1024 {
        return Err(io::Error::other("bundle metadata exceeds 1 MiB").into());
    }
    Ok(content)
}

async fn restore_into(
    client: &mut Client,
    bundle: &Path,
    run_id: &str,
    launched_path: Option<&str>,
) -> Result<Value> {
    use aidbg::rpc::{
        BreakpointKind, CaptureScope, InstallBreakpointRequest, ModuleOffsetLocation,
        RemoveBreakpointRequest, ScriptDocumentRequest, install_breakpoint_request::Location,
    };
    let content = read_bundle_metadata(&bundle.join("breakpoints.json"))?;
    let points: Vec<ReplayPoint> = serde_json::from_slice(&content)?;
    let status = client
        .run_status(Request::new(ScriptDocumentRequest {
            json: serde_json::to_vec(&serde_json::json!({"run_id": run_id}))?,
        }))
        .await?
        .into_inner();
    let status: Value = serde_json::from_slice(&status.json)?;
    let leader = status["pid"]
        .as_i64()
        .and_then(|pid| i32::try_from(pid).ok())
        .filter(|_| status["status"] == "paused")
        .ok_or_else(|| {
            io::Error::other("restore requires a live run paused before the breakpoint locations")
        })?;
    let original_executable = if launched_path.is_some()
        && points.iter().any(|point| {
            point
                .module
                .as_ref()
                .is_some_and(|module| module.build_id.is_none())
        }) {
        let path = bundle.join("manifest.json");
        let bytes = read_bundle_metadata(&path)?;
        let manifest: Value = serde_json::from_slice(&bytes)?;
        manifest["executable"]["path"].as_str().map(str::to_owned)
    } else {
        None
    };
    let mut requests = Vec::new();
    let mut live = std::collections::BTreeMap::<String, aidbg::script::RunRequest>::new();
    for point in points {
        let module = point
            .module
            .ok_or_else(|| io::Error::other("breakpoint has no mapped module"))?;
        let offset = point
            .module_offset
            .as_deref()
            .ok_or_else(|| io::Error::other("breakpoint has no module offset"))?;
        let read_rule = |key: &str| -> Result<_> {
            if !fs::symlink_metadata(bundle.join("rules"))?.is_dir() {
                return Err(io::Error::other("expected a regular rules directory").into());
            }
            let path = bundle.join(rule_path(key)?);
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err(io::Error::other("expected a regular rule source file").into());
            }
            super::script_client::read_source(&path)
        };
        let kind = match point.kind.as_str() {
            "hardware_execution" => BreakpointKind::Hardware,
            "software_execution" => BreakpointKind::Software,
            "hardware_read" => BreakpointKind::Read,
            "hardware_write" => BreakpointKind::Write,
            "hardware_read_write" => BreakpointKind::ReadWrite,
            _ => return Err(io::Error::other("unknown bundled breakpoint kind").into()),
        };
        let tid = match point.thread.as_deref() {
            None => None,
            Some("leader") => Some(leader),
            _ => {
                return Err(io::Error::other(
                    "cannot identify the original worker thread in the new run",
                )
                .into());
            }
        };
        let module = if original_executable.as_deref() == Some(module.path.as_str()) {
            launched_path.map(str::to_owned).unwrap_or(module.path)
        } else {
            module.build_id.unwrap_or(module.path)
        };
        let offset = super::parse_address(offset)?;
        if let Some(install) = point.live {
            let key = point
                .source
                .ok_or_else(|| io::Error::other("live breakpoint is missing its script"))?;
            let script = match live.entry(key) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let source = read_rule(entry.key())?;
                    entry.insert(aidbg::script::RunRequest {
                        source,
                        target_id: None,
                        run_id: Some(run_id.to_owned()),
                        timeout_ms: None,
                        replay_points: Vec::new(),
                    })
                }
            };
            script.replay_points.push(aidbg::script::LiveReplayPoint {
                original_breakpoint_id: point.breakpoint_id,
                ordinal: install.ordinal,
                requested_address: super::parse_address(&install.requested_address)?,
                module,
                offset,
                kind: point.kind,
                leader_only: tid.is_some(),
            });
            continue;
        }
        let source = point.source.as_deref().map(read_rule).transpose()?;
        requests.push((
            point.breakpoint_id,
            InstallBreakpointRequest {
                location: Some(Location::ModuleOffset(ModuleOffsetLocation {
                    module,
                    offset,
                    instance: None,
                })),
                run_id: Some(run_id.to_owned()),
                kind: kind as i32,
                scope: if point.scope == "process" {
                    CaptureScope::Process
                } else {
                    CaptureScope::Thread
                } as i32,
                length: point.length,
                timeout_ms: Some(point.timeout_ms),
                tid,
                rule_source: source,
                stop_after_hit: point.stop_after_hit,
                replay_export: point.export,
                ..Default::default()
            },
        ));
    }
    let mut results: Vec<Value> = Vec::new();
    let install: Result<()> = async {
        for (id, point) in requests {
                let reply = client.install_breakpoint(Request::new(point)).await?;
                let mut point: Value = serde_json::from_slice(&reply.into_inner().json)?;
                point["original_breakpoint_id"] = id.into();
                results.push(point);
        }
        for mut script in live.into_values() {
            script.replay_points.sort_by_key(|point| point.ordinal);
            let reply = client.script_run(Request::new(ScriptDocumentRequest { json: serde_json::to_vec(&script)? })).await?;
            let result: Value = serde_json::from_slice(&reply.into_inner().json)?;
            if result["status"] != "complete" {
                return Err(io::Error::other(result["issue"].as_str().unwrap_or("live breakpoint restore failed")).into());
            }
            let ids = result["breakpoint_ids"].as_array().ok_or_else(|| io::Error::other("missing restored breakpoint IDs"))?;
            for (point, id) in script.replay_points.iter().zip(ids) {
                results.push(serde_json::json!({"original_breakpoint_id": point.original_breakpoint_id, "breakpoint_id": id}));
            }
            if ids.len() != script.replay_points.len() {
                return Err(io::Error::other("unexpected restored breakpoint count").into());
            }
        }
        Ok(())
    }.await;
    if let Err(issue) = install {
        let mut cleanup = Vec::new();
        for point in results.iter().rev() {
            let Some(breakpoint_id) = point["breakpoint_id"].as_u64() else {
                continue;
            };
            if let Err(error) = client
                .remove_breakpoint(Request::new(RemoveBreakpointRequest {
                    pid: 0,
                    run_id: Some(run_id.to_owned()),
                    breakpoint_id,
                }))
                .await
            {
                cleanup.push(error.to_string());
            }
        }
        if cleanup.is_empty() {
            return Err(issue);
        }
        return Err(io::Error::other(format!(
            "{issue}; breakpoint restore rollback failed: {}",
            cleanup.join(", ")
        ))
        .into());
    }
    Ok(serde_json::json!({"status": "complete", "breakpoints": results}))
}
