use aidbg::Result;
use aidbg::coredump::{hash_reader, try_lock, valid_dump_id};
use aidbg::rpc::{
    Client, CoreMode, CoredumpJob, CoredumpJobState, CoredumpRequest, DownloadCoredumpRequest,
    GetCoredumpRequest, StartCoredumpRequest, coredump_chunk::Part,
};
use clap::{Args, ValueEnum};
use nix::libc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tonic::{Code, Request, Status};

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
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    pid: Option<i32>,
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

fn progress_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options
}

impl LocalDump {
    fn open(output: PathBuf, resume: bool) -> Result<Self> {
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
    if args.resume {
        if args.pid.is_some()
            || args.mode.is_some()
            || args.timeout_ms.is_some()
            || args.buffer_mib.is_some()
            || args.block_kib.is_some()
        {
            return Err(io::Error::other("resume takes the saved capture settings").into());
        }
        return Ok(None);
    }
    let pid = args
        .pid
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::other("a positive PID is required"))?;
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
        || !matches!(summary["status"].as_str(), Some("complete" | "partial"))
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
    let mut local = LocalDump::open(args.output, args.resume)?;
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
