#[path = "aidbg-server/target_policy.rs"]
mod target_policy;

#[path = "aidbg-server/run_jobs.rs"]
mod run_jobs;

#[path = "aidbg-server/breakpoint_service.rs"]
mod breakpoint_service;
#[path = "aidbg-server/coredump_store.rs"]
mod coredump_store;

use aidbg::rpc::{
    AssembleRequest, BreakpointCapabilitiesRequest, BreakpointEventsRequest, CoreMode,
    CoredumpChunk, CoredumpJob, CoredumpRequest, DisassembleRequest, DocumentReply,
    DownloadCoredumpRequest, EmulateRequest, FreezeMode, GetCoredumpRequest, InspectRequest,
    InstallBreakpointRequest, MAX_DOCUMENT, MAX_RPC, PatchRequest, ProfileRequest,
    QuerySnapshotRequest, RemoveBreakpointRequest, ResolveAddressRequest, SearchSymbolsRequest,
    SnapshotReply, SnapshotRequest, StartCoredumpRequest, StepWatchRequest, SymbolMatch,
    SymbolOverrideRequest, TargetCallRequest,
    coredump_chunk::Part,
    debugger_server::{Debugger, DebuggerServer},
    symbol_override_request::Action,
};
use aidbg::script::{self, Scripts};
use aidbg::{
    Result, Snapshot,
    selection::{Filter, with_id},
};
use breakpoint_service::Breakpoints;
use clap::Parser;
use coredump_store::DumpStore;
use prost::Message;
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::{Request, Response, Status, transport::Server};

#[derive(Parser)]
#[command(name = "aidbg-server", about = "Run the local aidbg debugger service", version = aidbg::BUILD_VERSION)]
struct Args {
    /// Absolute path in a private directory owned by this user.
    #[arg(long, required_unless_present = "listen")]
    socket: Option<PathBuf>,
    /// Opt in to a direct HTTP/2 TCP listener, for example 0.0.0.0:55051.
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// Private directory for complete JSON snapshots.
    #[arg(long)]
    state_dir: PathBuf,
    /// Seconds to retain completed coredumps and failed job statuses.
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u64).range(1..))]
    coredump_retention_secs: u64,
    /// Total quota in MiB for retained compressed coredumps.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..))]
    coredump_max_mib: u32,
    /// Concurrent open core targets retained by the server.
    #[arg(long, default_value_t = script::MAX_OPEN_CORES, value_parser = clap::value_parser!(u32).range(1..=i64::from(script::MAX_OPEN_CORES)))]
    max_open_cores: u32,
    /// JSON allowlist of build IDs and raw ELF function names for target_call.
    #[arg(long)]
    target_call_policy: Option<PathBuf>,
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

fn validate_capture(
    req: &CoredumpRequest,
) -> std::result::Result<(CoreMode, aidbg::coredump::CaptureOptions), Status> {
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
    Ok((mode, options))
}

struct Service {
    scripts: Arc<Scripts>,
    script_slots: Arc<tokio::sync::Semaphore>,
    run_slots: Arc<tokio::sync::Semaphore>,
    runs: Arc<run_jobs::RunJobs>,
    store: Arc<Store>,
    // The blocking job owns this guard until capture has finished cleanup.
    capture_lock: Arc<Mutex<()>>,
    profiler: Arc<tokio::sync::Semaphore>,
    overrides: Arc<aidbg::symbols::Overrides>,
    code_engine: Arc<tokio::sync::Semaphore>,
    target_policy: Arc<target_policy::Policy>,
    coredumps: Arc<tokio::sync::Semaphore>,
    dump_store: Arc<DumpStore>,
    breakpoints: Breakpoints,
}

struct CancelRun(Arc<AtomicBool>);

impl Drop for CancelRun {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl Service {
    async fn script_task<T: serde::Serialize + Send + 'static>(
        &self,
        task: impl FnOnce(Arc<Scripts>) -> std::result::Result<T, Status> + Send + 'static,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let permit = self
            .script_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("script workers are busy"))?;
        let scripts = self.scripts.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            document(task(scripts)?)
        })
        .await
        .map_err(internal)?
    }
}

fn script_request<T: serde::de::DeserializeOwned>(
    request: Request<aidbg::rpc::ScriptDocumentRequest>,
) -> std::result::Result<T, Status> {
    serde_json::from_slice(&request.into_inner().json)
        .map_err(|e| Status::invalid_argument(e.to_string()))
}

fn script_error(error: Box<dyn std::error::Error + Send + Sync>) -> Status {
    if let Some(issue) = error.downcast_ref::<aidbg::Diagnostic>() {
        let code = match issue.code {
            "TARGET_GONE" | "RUN_GONE" | "RULE_NOT_FOUND" | "BREAKPOINT_NOT_FOUND" => {
                tonic::Code::NotFound
            }
            "INVALID_ARGUMENT" | "CONFLICTING_TARGET" => tonic::Code::InvalidArgument,
            "TARGET_CALL_DENIED" => tonic::Code::PermissionDenied,
            "RUN_CANCELLED" => tonic::Code::Cancelled,
            _ => tonic::Code::FailedPrecondition,
        };
        return Status::with_details(
            code,
            &issue.message,
            serde_json::to_vec(issue).unwrap_or_default().into(),
        );
    }
    Status::failed_precondition(error.to_string())
}

fn conflicting_target(choices: &str) -> Status {
    script_error(
        aidbg::Diagnostic::new(
            "CONFLICTING_TARGET",
            format!("Specify only one target: {choices}"),
            None,
        )
        .into(),
    )
}

#[tonic::async_trait]
impl Debugger for Service {
    async fn server_info(
        &self,
        _: Request<aidbg::rpc::ServerInfoRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        document(serde_json::json!({
            "name": "aidbg-server",
            "version": aidbg::VERSION,
            "revision": aidbg::BUILD_REVISION,
            "architecture": std::env::consts::ARCH,
            "environment": {
                "va_bits": user_va_bits(),
                "asan_high_address": "0x500000000000",
                "asan_high_address_mappable": address_mappable(0x500000000000),
            },
            "limits": {"max_open_cores": self.scripts.max_open_cores()},
            "capabilities": ["run_control", "run_breakpoints", "live_inspect", "live_memory_search", "connect", "retained_core", "core_queries", "dump_coverage", "script_return", "detached_run", "core_memory_search", "export_bundle", "target_call_policy", "core_emulation"]
        }))
    }

    type CoredumpStream = ReceiverStream<std::result::Result<CoredumpChunk, Status>>;
    type DownloadCoredumpStream = Self::CoredumpStream;
    type DownloadCoreImagesStream = Self::CoredumpStream;

    async fn script_api(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        document(script::api(script_request(request)?).map_err(script_error)?)
    }

    async fn script_check(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request = script_request(request)?;
        self.script_task(move |scripts| scripts.check(request).map_err(script_error))
            .await
    }

    async fn script_run(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request: script::RunRequest = script_request(request)?;
        match (&request.run_id, &request.target_id) {
            (Some(run_id), None) => {
                let budget = request.budget().map_err(script_error)?;
                let (_, control) = self.runs.get(run_id)?.target()?;
                let breakpoints = self.breakpoints.clone();
                let lock = Arc::clone(&self.capture_lock);
                self.script_task(move |scripts| {
                    let js = scripts
                        .compile_live(&request.source)
                        .map_err(script_error)?;
                    let _guard = lock.blocking_lock();
                    breakpoints.script_run(
                        control,
                        js,
                        request.source,
                        request.replay_points,
                        budget,
                    )
                })
                .await
            }
            (None, Some(_)) => {
                if !request.replay_points.is_empty() {
                    return Err(Status::invalid_argument(
                        "breakpoint replay requires a live run",
                    ));
                }
                self.script_task(move |scripts| scripts.run(request).map_err(script_error))
                    .await
            }
            (Some(_), Some(_)) => Err(conflicting_target("run_id or target_id")),
            _ => Err(Status::invalid_argument(
                "provide exactly one of run_id or target_id",
            )),
        }
    }

    async fn run_target(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let args: aidbg::run::RunRequest = script_request(request)?;
        let permit = self
            .run_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("run workers are busy"))?;
        let scripts = self.scripts.clone();
        let dumps = self.dump_store.clone();
        let dump_slots = self.coredumps.clone();
        let detached = (args.detach || args.pause_at_entry)
            .then(|| self.runs.reserve())
            .transpose()?;
        let publish = self.breakpoints.publisher();
        let cancelled = detached.as_ref().map_or_else(
            || Arc::new(AtomicBool::new(false)),
            |(_, job, _)| job.cancelled.clone(),
        );
        let job = detached
            .as_ref()
            .map(|(id, job, _)| (id.clone(), job.clone()));
        let blocking_cancellation = job.is_none().then(|| CancelRun(cancelled.clone()));
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (state, observations) = detached.map_or((None, None), |(_, job, observations)| {
                (Some(job), Some(observations))
            });
            let execute = || {
                if cancelled.load(Ordering::Relaxed) {
                    return Err(Status::cancelled("Run cancelled before launch"));
                }
                let js = args
                    .signal_source
                    .as_deref()
                    .map(|source| scripts.compile_signal(source))
                    .transpose()
                    .map_err(script_error)?;
                aidbg::run::execute(
                    args,
                    js.as_deref(),
                    &|| cancelled.load(Ordering::Relaxed),
                    |pid, paused| {
                        if let Some(job) = &state {
                            job.launched(pid, paused);
                        }
                    },
                    observations,
                    publish,
                    |pid, capture| {
                        let _permit = dump_slots.try_acquire()?;
                        dumps.capture_signal(pid, capture)
                    },
                )
                .map_err(script_error)
            };
            let result = execute();
            if let Some(job) = state {
                job.finish(result);
                Ok(None)
            } else {
                result.map(Some)
            }
        });
        if let Some((id, job)) = job {
            job.wait_ready().await;
            return document(job.document(&id, false)?);
        }
        let _cancel_on_drop = blocking_cancellation;
        document(worker.await.map_err(internal)??)
    }

    async fn run_status(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request: aidbg::run::RunId = script_request(request)?;
        document(
            self.runs
                .get(&request.run_id)?
                .document(&request.run_id, false)?,
        )
    }

    async fn run_pause(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        self.set_run_paused(script_request(request)?, true).await
    }

    async fn run_list(
        &self,
        _: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        document(self.runs.list()?)
    }

    async fn run_continue(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        self.set_run_paused(script_request(request)?, false).await
    }

    async fn step_run(
        &self,
        request: Request<aidbg::rpc::StepRunRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let (_, control) = self.runs.get(&req.run_id)?.target()?;
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(control.step(req).map_err(script_error)?)
        })
        .await
        .map_err(internal)?
    }

    async fn run_cancel(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request: aidbg::run::RunId = script_request(request)?;
        document(
            self.runs
                .get(&request.run_id)?
                .document(&request.run_id, true)?,
        )
    }

    async fn core_open(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request: script::OpenRequest = script_request(request)?;
        let id = request
            .dump_id
            .filter(|_| request.path.is_none())
            .ok_or_else(|| {
                Status::invalid_argument("server core_open requires a retained dump_id")
            })?;
        let store = self.dump_store.clone();
        self.script_task(move |scripts| {
            let download = store.download(&id, 0)?;
            scripts
                .open_compressed(download.reader, request.symbols)
                .map_err(script_error)
        })
        .await
    }

    async fn core_close(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request: script::CloseRequest = script_request(request)?;
        self.script_task(move |scripts| scripts.close(&request.target_id).map_err(script_error))
            .await
    }

    async fn search_memory(
        &self,
        request: Request<aidbg::rpc::SearchMemoryRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request = request.into_inner();
        if request.pid.is_some() || request.run_id.is_some() {
            if !request.target_id.is_empty() || (request.pid.is_some() && request.run_id.is_some())
            {
                return Err(conflicting_target("target_id, pid or run_id"));
            }
            let mut pid = request.pid.unwrap_or_default();
            self.run_breakpoint_target(request.run_id.as_deref(), &mut pid)?;
            validate_pid(pid)?;
            return self
                .script_task(move |_| script::search_live(pid, &request).map_err(script_error))
                .await;
        }
        self.script_task(move |scripts| scripts.search_memory(request).map_err(script_error))
            .await
    }

    async fn read_memory(
        &self,
        request: Request<aidbg::rpc::ReadMemoryRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request = request.into_inner();
        match (&request.target_id, request.pid, &request.run_id) {
            (Some(_), None, None) => {
                self.script_task(move |scripts| scripts.read_memory(request).map_err(script_error))
                    .await
            }
            (None, None, Some(run_id)) => {
                let (_, control) = self.runs.get(run_id)?.target()?;
                self.script_task(move |_| control.read_memory(request).map_err(script_error))
                    .await
            }
            (None, Some(pid), None) => {
                validate_pid(pid)?;
                self.script_task(move |_| script::read_live(pid, &request).map_err(script_error))
                    .await
            }
            (None, None, None) => Err(Status::invalid_argument("provide target_id, pid or run_id")),
            _ => Err(conflicting_target("target_id, pid or run_id")),
        }
    }

    async fn observe_threads(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request: aidbg::script_observation::Request = script_request(request)?;
        match (&request.target_id, request.pid, &request.run_id) {
            (Some(_), None, None) => {
                self.script_task(move |scripts| {
                    scripts.observe_threads(request).map_err(script_error)
                })
                .await
            }
            (None, None, Some(run_id)) => {
                let (pid, _) = self.runs.get(run_id)?.target()?;
                self.script_task(move |_| {
                    script::synchronization::live(pid, request).map_err(script_error)
                })
                .await
            }
            (None, Some(pid), None) => {
                validate_pid(pid)?;
                self.script_task(move |_| {
                    script::synchronization::live(pid, request).map_err(script_error)
                })
                .await
            }
            (None, None, None) => Err(Status::invalid_argument("provide target_id, pid or run_id")),
            _ => Err(conflicting_target("target_id, pid or run_id")),
        }
    }

    async fn pointer_chain(
        &self,
        request: Request<aidbg::rpc::PointerChainRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let request = request.into_inner();
        match (
            request.target_id.is_empty(),
            request.pid,
            request.run_id.as_deref(),
        ) {
            (false, None, None) => {
                self.script_task(move |scripts| {
                    scripts.pointer_chain(request).map_err(script_error)
                })
                .await
            }
            (true, Some(pid), None) => {
                validate_pid(pid)?;
                self.script_task(move |_| {
                    script::pointer_chain_live(pid, request.base, request.offsets)
                        .map_err(script_error)
                })
                .await
            }
            (true, None, Some(run_id)) => {
                let (_, control) = self.runs.get(run_id)?.target()?;
                self.script_task(move |_| control.pointer_chain(request).map_err(script_error))
                    .await
            }
            (true, None, None) => Err(Status::invalid_argument("provide target_id, pid or run_id")),
            _ => Err(conflicting_target("target_id, pid or run_id")),
        }
    }

    async fn start_coredump(
        &self,
        request: Request<StartCoredumpRequest>,
    ) -> std::result::Result<Response<CoredumpJob>, Status> {
        let StartCoredumpRequest { dump_id, capture } = request.into_inner();
        let req = capture.ok_or_else(|| Status::invalid_argument("capture request is missing"))?;
        let mut capture = req.clone();
        let selected_run = match self.capture_target(&mut capture) {
            Ok(run) => run,
            Err(error)
                if matches!(
                    error.code(),
                    tonic::Code::FailedPrecondition | tonic::Code::NotFound
                ) =>
            {
                let store = self.dump_store.clone();
                let job = tokio::task::spawn_blocking(move || {
                    store.existing_capture(&dump_id, &req.encode_to_vec())
                })
                .await
                .map_err(internal)?;
                return match job {
                    Ok(job) => Ok(Response::new(job)),
                    Err(status) if status.code() == tonic::Code::NotFound => Err(error),
                    Err(status) => Err(status),
                };
            }
            Err(error) => return Err(error),
        };
        let (mode, options) = validate_capture(&capture)?;
        let pid = capture.pid;
        let store = Arc::clone(&self.dump_store);
        let slots = Arc::clone(&self.coredumps);
        let lock = Arc::clone(&self.capture_lock);
        let breakpoints = self.breakpoints.clone();
        let runs = Arc::clone(&self.runs);
        // Once reserved, the job outlives the RPC, including cancellation
        // before the Start response arrives at the client.
        let job = tokio::spawn(async move {
            let reserve = Arc::clone(&store);
            let id = dump_id.clone();
            let (job, worker) = tokio::task::spawn_blocking(move || {
                let identity = aidbg::coredump::target_identity(pid);
                let (job, worker) = reserve.reserve(&id, req.encode_to_vec())?;
                let worker = worker.map(|guard| (guard, identity));
                Ok::<_, Status>((job, worker))
            })
            .await
            .map_err(internal)??;
            if let Some((worker, identity)) = worker {
                tokio::spawn(async move {
                    let _worker = worker;
                    let result = async {
                        let options = options.for_process(identity?);
                        let permit = slots.acquire_owned().await?;
                        let guard = lock.lock_owned().await;
                        let worker_store = Arc::clone(&store);
                        let id = dump_id.clone();
                        tokio::task::spawn_blocking(move || -> Result<()> {
                            let _permit = permit;
                            let directory = worker_store.path(&id);
                            let control = match selected_run {
                                Some(control) => Some(control),
                                None => runs
                                    .control_for_pid(pid)?
                                    .or_else(|| breakpoints.inspect_control(pid)),
                            };
                            let dump = if let Some(control) = control {
                                let dump = control.capture_core(mode, options, directory)?;
                                drop(guard);
                                dump
                            } else {
                                aidbg::coredump::prepare(
                                    pid,
                                    mode,
                                    options,
                                    &directory,
                                    &|| false,
                                    || drop(guard),
                                )?
                            };
                            worker_store.finish(&id, dump)
                        })
                        .await?
                    }
                    .await;
                    if let Err(error) = result {
                        let _ = tokio::task::spawn_blocking(move || {
                            if let Err(error) = store.fail(&dump_id, error.to_string()) {
                                eprintln!("Could not save failed coredump status: {error}");
                            }
                        })
                        .await;
                    }
                });
            }
            Ok::<_, Status>(job)
        })
        .await
        .map_err(internal)??;
        Ok(Response::new(job))
    }

    async fn get_coredump(
        &self,
        request: Request<GetCoredumpRequest>,
    ) -> std::result::Result<Response<CoredumpJob>, Status> {
        let request = request.into_inner();
        let store = Arc::clone(&self.dump_store);
        let job = tokio::task::spawn_blocking(move || store.get(&request.dump_id))
            .await
            .map_err(internal)??;
        Ok(Response::new(job))
    }

    async fn retain_coredump(
        &self,
        request: Request<aidbg::rpc::RetainCoredumpRequest>,
    ) -> std::result::Result<Response<CoredumpJob>, Status> {
        let req = request.into_inner();
        let store = self.dump_store.clone();
        let job =
            tokio::task::spawn_blocking(move || store.retain(&req.dump_id, req.retention_secs))
                .await
                .map_err(internal)??;
        Ok(Response::new(job))
    }

    async fn upload_artifact(
        &self,
        request: Request<tonic::Streaming<aidbg::rpc::ArtifactChunk>>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        use aidbg::rpc::{artifact_chunk::Part, artifact_header::Kind};
        use tokio::io::AsyncWriteExt;
        let _permit = self
            .coredumps
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("artifact workers are busy"))?;
        let mut stream = request.into_inner();
        let idle = std::time::Duration::from_secs(30);
        let mut next = async || {
            tokio::time::timeout(idle, stream.message())
                .await
                .map_err(|_| Status::deadline_exceeded("artifact upload stalled"))?
        };
        let Some(Part::Header(header)) = next().await?.and_then(|part| part.part) else {
            return Err(Status::invalid_argument("expected an artifact header"));
        };
        let kind = Kind::try_from(header.kind)
            .map_err(|_| Status::invalid_argument("unknown artifact kind"))?;
        let store = self.dump_store.clone();
        if header.size < 20 || header.size > store.upload_limit(kind) {
            return Err(Status::resource_exhausted(
                "artifact size exceeds upload limit or is too small",
            ));
        }
        let temporary =
            tempfile::NamedTempFile::new_in(store.upload_directory()).map_err(internal)?;
        let mut file = tokio::fs::File::from_std(temporary.reopen().map_err(internal)?);
        let mut received = 0;
        while let Some(chunk) = next().await? {
            let Some(Part::Data(bytes)) = chunk.part else {
                return Err(Status::invalid_argument("unexpected artifact header"));
            };
            received += bytes.len() as u64;
            if received > header.size || bytes.is_empty() {
                return Err(Status::invalid_argument(
                    "artifact size does not match the header",
                ));
            }
            file.write_all(&bytes).await.map_err(internal)?;
        }
        if received != header.size {
            return Err(Status::invalid_argument(
                "artifact upload ended before the declared size",
            ));
        }
        file.flush().await.map_err(internal)?;
        drop(file);
        let permit = _permit;
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.commit_upload(temporary, kind)
        })
        .await
        .map_err(internal)?
        .map_err(script_error)?;
        document(result)
    }

    async fn download_coredump(
        &self,
        request: Request<DownloadCoredumpRequest>,
    ) -> std::result::Result<Response<Self::DownloadCoredumpStream>, Status> {
        let req = request.into_inner();
        let store = Arc::clone(&self.dump_store);
        let mut download =
            tokio::task::spawn_blocking(move || store.download(&req.dump_id, req.offset))
                .await
                .map_err(internal)??;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        tokio::task::spawn_blocking(move || {
            let mut buffer = vec![0; 64 * 1024];
            while !sender.is_closed() && download.reader.limit() != 0 {
                let chunk = match download.reader.read(&mut buffer) {
                    Ok(0) => Err(Status::data_loss("saved coredump ended prematurely")),
                    Ok(n) => Ok(CoredumpChunk {
                        part: Some(Part::Data(buffer[..n].to_vec())),
                    }),
                    Err(error) => Err(internal(error)),
                };
                let failed = chunk.is_err();
                if sender.blocking_send(chunk).is_err() || failed {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn download_core_images(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<Self::DownloadCoreImagesStream>, Status> {
        let request: script::CoreImagesRequest = script_request(request)?;
        let store = self.dump_store.clone();
        let permit = self
            .script_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("core workers are busy"))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = (|| {
                let download = store.download(&request.dump_id, 0)?;
                let (info, images) =
                    Scripts::core_images(download.reader, request.symbols).map_err(script_error)?;
                for (name, bytes) in images {
                    let header = serde_json::to_vec(&serde_json::json!({
                        "name": name, "size": bytes.len(),
                        "executable": info["executable"], "architecture": info["architecture"],
                        "server_version": aidbg::BUILD_VERSION,
                    }))
                    .map_err(internal)?;
                    if sender
                        .blocking_send(Ok(CoredumpChunk {
                            part: Some(Part::SummaryJson(header)),
                        }))
                        .is_err()
                    {
                        break;
                    }
                    for data in bytes.chunks(64 * 1024) {
                        if sender
                            .blocking_send(Ok(CoredumpChunk {
                                part: Some(Part::Data(data.to_vec())),
                            }))
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                let _ = sender.blocking_send(Err(error));
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }

    async fn coredump(
        &self,
        request: Request<CoredumpRequest>,
    ) -> std::result::Result<Response<Self::CoredumpStream>, Status> {
        let mut req = request.into_inner();
        let selected_run = self.capture_target(&mut req)?;
        let (mode, options) = validate_capture(&req)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        let lock = Arc::clone(&self.capture_lock);
        let slots = Arc::clone(&self.coredumps);
        let breakpoints = self.breakpoints.clone();
        let runs = self.runs.clone();
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
                let control = match selected_run {
                    Some(control) => Some(control),
                    None => runs
                        .control_for_pid(req.pid)?
                        .or_else(|| breakpoints.inspect_control(req.pid)),
                };
                let dump = if let Some(control) = control {
                    let result = control.capture_core(mode, options, store.0.clone());
                    drop(guard);
                    result.map_err(script_error)?
                } else {
                    aidbg::coredump::prepare(
                        req.pid,
                        mode,
                        options,
                        &store.0,
                        &|| chunks.is_closed(),
                        || drop(guard),
                    )
                    .map_err(internal)?
                };
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

    async fn target_call(
        &self,
        request: Request<TargetCallRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let peer_address = request.remote_addr();
        let peer = request
            .extensions()
            .get::<tonic::transport::server::UdsConnectInfo>()
            .and_then(|info| info.peer_cred);
        let req = request.into_inner();
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        let policy = self.target_policy.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let context = serde_json::json!({
                "attempt": policy.next_attempt(),
                "peer_address": peer_address,
                "peer_uid": peer.map(|credentials| credentials.uid()),
                "peer_pid": peer.and_then(|credentials| credentials.pid()),
                "pid": req.pid, "tid": req.tid, "module": req.module, "symbol": req.symbol,
                "allow_side_effects": req.allow_side_effects,
            });
            policy.record("requested", &context, serde_json::Value::Null).map_err(internal)?;
            let outcome = (|| {
                validate_pid(req.pid)?;
                if breakpoints.contains(req.pid) {
                    return Err(Status::failed_precondition("an active breakpoint session owns this PID"));
                }
                aidbg::target_call::run(req, |build_id, symbols, address| {
                    let authorization = policy.check(build_id, symbols);
                    policy.record(if authorization.is_ok() { "authorized" } else { "denied" }, &context, serde_json::json!({
                        "build_id": build_id, "symbols": symbols, "address": aidbg::hex(address),
                    }))?;
                    authorization
                }).map_err(script_error)
            })();
            policy.record("finished", &context, match &outcome {
                Ok(report) => serde_json::json!({"status": report.status}),
                Err(status) => serde_json::json!({"status": "error", "code": status.code().to_string()}),
            }).map_err(internal)?;
            document(outcome?)
        })
        .await
        .map_err(internal)?
    }

    async fn step_watch(
        &self,
        request: Request<StepWatchRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            if breakpoints.contains(req.pid) {
                return Err(Status::failed_precondition(
                    "an active breakpoint session owns this PID",
                ));
            }
            document(
                aidbg::watch_step::run(req)
                    .map_err(|e| Status::failed_precondition(e.to_string()))?,
            )
        })
        .await
        .map_err(internal)?
    }

    async fn snapshot(
        &self,
        request: Request<SnapshotRequest>,
    ) -> std::result::Result<Response<SnapshotReply>, Status> {
        let req = request.into_inner();
        let mode = FreezeMode::try_from(req.freeze)
            .map_err(|_| Status::invalid_argument("unknown freeze mode"))?;
        let filter =
            Filter::parse(req.selection).map_err(|e| Status::invalid_argument(e.to_string()))?;
        if let Some(id) = req.run_id {
            if req.pid != 0 {
                return Err(conflicting_target("pid or run_id"));
            }
            let snapshot = self.runs.get(&id)?.snapshot(mode).await?;
            let store = self.store.clone();
            let reply = tokio::task::spawn_blocking(move || store.save(snapshot, filter))
                .await
                .map_err(internal)?
                .map_err(internal)?;
            return Ok(Response::new(reply));
        }
        validate_pid(req.pid)?;
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

    async fn rule_define(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req: script::RuleDefine = script_request(request)?;
        let name = req.name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(Status::invalid_argument(
                "rule name must be 1–128 bytes after trimming",
            ));
        }
        let exports = matches!(req.mode, script::RuleMode::Exports);
        let (js, names) = self.compile_rule(req.source.clone(), true, exports).await?;
        let name = name.to_owned();
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.define_rule(name, js, req.source, names)?)
        })
        .await
        .map_err(internal)?
    }

    async fn rule_list(
        &self,
        _: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || document(breakpoints.list_rules()))
            .await
            .map_err(internal)?
    }

    async fn rule_update(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req: script::RuleUpdate = script_request(request)?;
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        let exports = breakpoints.rule_exports(req.rule_id)?;
        let (js, names) = self.compile_rule(req.source.clone(), true, exports).await?;
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.update_rule(req.rule_id, js, req.source, names)?)
        })
        .await
        .map_err(internal)?
    }

    async fn rule_remove(
        &self,
        request: Request<aidbg::rpc::ScriptDocumentRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req: script::RuleId = script_request(request)?;
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.remove_rule(req.rule_id)?)
        })
        .await
        .map_err(internal)?
    }

    async fn install_breakpoint(
        &self,
        request: Request<InstallBreakpointRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let mut req = request.into_inner();
        let run = self.run_breakpoint_target(req.run_id.as_deref(), &mut req.pid)?;
        validate_pid(req.pid)?;
        if [
            req.rule_id.is_some(),
            req.rule_source.is_some(),
            req.handler.is_some(),
        ]
        .into_iter()
        .filter(|provided| *provided)
        .count()
            > 1
        {
            return Err(Status::invalid_argument(
                "provide only one of handler, rule_id, or rule_source",
            ));
        }
        let callback_js = match req.rule_source.take() {
            Some(source) => {
                let export = req.replay_export.take();
                let (js, names) = self
                    .compile_rule(source.clone(), false, export.is_some())
                    .await?;
                if let Some(export) = &export
                    && !names.as_ref().is_some_and(|names| names.contains(export))
                {
                    return Err(Status::invalid_argument(
                        "replayed callback export is absent from its rule source",
                    ));
                }
                Some((js, source, export))
            }
            None if req.replay_export.is_some() => {
                return Err(Status::invalid_argument(
                    "replay_export requires rule_source",
                ));
            }
            None => None,
        };
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        let overrides = self.overrides.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.install(
                req,
                callback_js,
                run,
                &overrides.list().map_err(internal)?,
            )?)
        })
        .await
        .map_err(internal)?
    }

    async fn remove_breakpoint(
        &self,
        request: Request<RemoveBreakpointRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let mut req = request.into_inner();
        let run = if let Some(id) = req.run_id.as_deref() {
            if req.pid != 0 {
                return Err(conflicting_target("pid or run_id"));
            }
            let target = match self.runs.get(id) {
                Ok(job) => job.target().ok(),
                Err(status) if status.code() == tonic::Code::NotFound => None,
                Err(status) => return Err(status),
            };
            let Some((pid, control)) = target else {
                return document(
                    serde_json::json!({"breakpoint_id": req.breakpoint_id, "status": "already_removed", "cleanup": null}),
                );
            };
            req.pid = pid;
            Some(control)
        } else {
            self.run_breakpoint_target(None, &mut req.pid)?
        };
        validate_pid(req.pid)?;
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.remove(req.pid, req.breakpoint_id, run)?)
        })
        .await
        .map_err(internal)?
    }

    async fn update_breakpoint(
        &self,
        request: Request<aidbg::rpc::UpdateBreakpointRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            document(breakpoints.update(req)?)
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
        let mut req = request.into_inner();
        if req.target_id.is_some() {
            if req.pid != 0 || req.run_id.is_some() {
                return Err(conflicting_target("pid, target_id or run_id"));
            }
            return self
                .script_task(move |scripts| scripts.symbols(req).map_err(script_error))
                .await;
        }
        if let Some(id) = req.run_id.as_deref() {
            if req.pid != 0 {
                return Err(conflicting_target("pid or run_id"));
            }
            req.pid = self.runs.get(id)?.target()?.0;
        }
        validate_pid(req.pid)?;
        let mode = SymbolMatch::try_from(req.match_mode)
            .map_err(|_| Status::invalid_argument("unknown symbol match mode"))?;
        let overrides = Arc::clone(&self.overrides);
        tokio::task::spawn_blocking(move || {
            let result = aidbg::symbols::search(
                req.pid,
                &req.pattern,
                mode,
                req.module.as_deref(),
                req.limit.unwrap_or(256),
                &overrides.list().map_err(internal)?,
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
        if req.target_id.is_some() {
            return self
                .script_task(move |scripts| scripts.resolve(req).map_err(script_error))
                .await;
        }
        validate_pid(req.pid)?;
        let overrides = Arc::clone(&self.overrides);
        tokio::task::spawn_blocking(move || {
            let result =
                aidbg::symbols::resolve(req.pid, req.address, &overrides.list().map_err(internal)?)
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
        let mut req = request.into_inner();
        if req.target_id.is_some() {
            if req.pid != 0 || req.run_id.is_some() {
                return Err(conflicting_target("pid, target_id or run_id"));
            }
            return self
                .script_task(move |scripts| scripts.disassemble(req).map_err(script_error))
                .await;
        }
        let run = if let Some(id) = req.run_id.as_deref() {
            if req.pid != 0 {
                return Err(conflicting_target("pid or run_id"));
            }
            let (pid, control) = self.runs.get(id)?.target()?;
            req.pid = pid;
            Some(control)
        } else {
            None
        };
        validate_pid(req.pid)?;
        tokio::task::spawn_blocking(move || {
            if let Some(control) = run {
                return document(control.disassemble(req).map_err(script_error)?);
            }
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
        request: Request<BreakpointCapabilitiesRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        if req.run_id.is_some() && req.pid.is_some() {
            return Err(conflicting_target("pid or run_id"));
        }
        let control = if let Some(run_id) = req.run_id.as_deref() {
            Some(self.runs.get(run_id)?.target()?.1)
        } else if let Some(pid) = req.pid {
            validate_pid(pid)?;
            self.runs.control_for_pid(pid)?
        } else {
            None
        };
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let control =
                control.or_else(|| req.pid.and_then(|pid| breakpoints.inspect_control(pid)));
            let mut result = match (control, req.pid) {
                (Some(control), _) => control.capabilities(),
                (None, Some(pid)) => aidbg::breakpoint::capabilities_for(pid),
                (None, None) => aidbg::breakpoint::probe_capabilities(),
            }
            .map_err(script_error)?;
            if result.get("used_slots").is_none() {
                result["used_slots"] = serde_json::json!([]);
            }
            document(result)
        })
        .await
        .map_err(internal)?
    }

    async fn breakpoint_list(
        &self,
        request: Request<BreakpointCapabilitiesRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        if req.pid.is_some() && req.run_id.is_some() {
            return Err(conflicting_target("pid or run_id"));
        }
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let scoped = req.pid.is_some() || req.run_id.is_some();
        let controls = if let Some(id) = req.run_id {
            self.runs
                .get(&id)?
                .target()
                .ok()
                .into_iter()
                .collect::<Vec<_>>()
        } else if let Some(pid) = req.pid {
            validate_pid(pid)?;
            self.runs
                .control_for_pid(pid)?
                .or_else(|| self.breakpoints.inspect_control(pid))
                .map(|control| (pid, control))
                .into_iter()
                .collect()
        } else {
            let mut controls = self.runs.live_controls()?;
            controls.extend(self.breakpoints.live_controls());
            controls
        };
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let mut rows = Vec::new();
            for (pid, owner) in controls {
                let points = match owner.list() {
                    Ok(points) => points,
                    Err(issue) if scoped => return Err(script_error(issue)),
                    Err(_) => continue,
                };
                for point in points {
                    let mut row = serde_json::to_value(point).map_err(internal)?;
                    row["pid"] = pid.into();
                    rows.push(row);
                }
            }
            rows.sort_by_key(|row| row["breakpoint_id"].as_u64());
            document(serde_json::json!({"breakpoints": rows}))
        })
        .await
        .map_err(internal)?
    }

    async fn profile(
        &self,
        request: Request<ProfileRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        validate_pid(req.pid)?;
        let duration = req.duration_ms.unwrap_or(1000);
        let frequency = req.frequency_hz.unwrap_or(99);
        if !(10..=10_000).contains(&duration)
            || !(1..=1000).contains(&frequency)
            || req.tid.is_some_and(|tid| tid <= 0)
        {
            return Err(Status::invalid_argument(
                "expected duration 10–10000 ms, frequency 1–1000 Hz and a positive TID",
            ));
        }
        let permit = Arc::clone(&self.profiler)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("a perf collection is already running"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = aidbg::perf::run(req.pid, req.stack, duration, frequency, req.tid)
                .map_err(|e| Status::failed_precondition(e.to_string()))?;
            document(result)
        })
        .await
        .map_err(internal)?
    }

    async fn symbol_override(
        &self,
        request: Request<SymbolOverrideRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let overrides = Arc::clone(&self.overrides);
        tokio::task::spawn_blocking(move || {
            let failed = |e: Box<dyn std::error::Error + Send + Sync>| {
                Status::failed_precondition(e.to_string())
            };
            match request.into_inner().action {
                Some(Action::Set(args)) => {
                    validate_pid(args.pid)?;
                    document(
                        overrides
                            .set(args.pid, args.address, args.length, args.name)
                            .map_err(failed)?,
                    )
                }
                Some(Action::RemoveId(id)) => document(overrides.remove(&id).map_err(failed)?),
                Some(Action::List(true)) => document(overrides.list().map_err(internal)?),
                _ => Err(Status::invalid_argument(
                    "select a symbol override operation",
                )),
            }
        })
        .await
        .map_err(internal)?
    }

    async fn inspect(
        &self,
        request: Request<InspectRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let mut req = request.into_inner();
        if req.target_id.is_some() {
            return self
                .script_task(move |scripts| scripts.inspect_core(req).map_err(script_error))
                .await;
        }
        if req.run_id.is_none() && (req.frame_index.is_some() || !req.expressions.is_empty()) {
            return Err(Status::invalid_argument(
                "frame_index and expressions require run_id or target_id",
            ));
        }

        let run = self.run_breakpoint_target(req.run_id.as_deref(), &mut req.pid)?;
        validate_pid(req.pid)?;
        if req.tid.is_some_and(|tid| tid <= 0) {
            return Err(Status::invalid_argument("expected a positive TID"));
        }
        let guard = Arc::clone(&self.capture_lock).lock_owned().await;
        let breakpoints = self.breakpoints.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
            if let Some(control) = run.or_else(|| breakpoints.inspect_control(req.pid)) {
                return document(control.inspect(req).map_err(script_error)?);
            }
            let report = aidbg::symbols::inspect(
                req.pid,
                req.tid,
                req.expression,
                req.module.as_deref(),
                req.instance,
                req.timeout_ms,
                req.expand,
            )
            .map_err(script_error)?;
            document(report)
        })
        .await
        .map_err(internal)?
    }

    async fn assemble(
        &self,
        request: Request<AssembleRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let req = request.into_inner();
        self.run_code_job(move || aidbg::code::assemble(req.address, &req.source))
            .await
    }

    async fn plan_patch(
        &self,
        request: Request<PatchRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let scripts = self.scripts.clone();
        self.run_code_job(move || scripts.patch(request.into_inner()))
            .await
    }

    async fn emulate(
        &self,
        request: Request<EmulateRequest>,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let scripts = self.scripts.clone();
        self.run_code_job(move || scripts.emulate(request.into_inner()))
            .await
    }
}

impl Service {
    async fn compile_rule(
        &self,
        source: String,
        validate: bool,
        exports: bool,
    ) -> std::result::Result<(String, Option<Vec<String>>), Status> {
        let permit = self
            .script_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("script workers are busy"))?;
        let scripts = Arc::clone(&self.scripts);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let js = scripts.compile_breakpoint(&source).map_err(script_error)?;
            let names = if exports {
                Some(
                    aidbg::breakpoint::CallbackSource::validate_exports(&js)
                        .map_err(script_error)?,
                )
            } else {
                if validate {
                    aidbg::breakpoint::CallbackSource::validate(&js).map_err(script_error)?;
                }
                None
            };
            Ok((js, names))
        })
        .await
        .map_err(internal)?
    }

    async fn set_run_paused(
        &self,
        request: aidbg::run::RunId,
        paused: bool,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let job = self.runs.get(&request.run_id)?;
        job.target()?;
        job.set_paused(paused).await?;
        document(job.document(&request.run_id, false)?)
    }

    fn capture_target(
        &self,
        req: &mut CoredumpRequest,
    ) -> std::result::Result<Option<aidbg::breakpoint::Control>, Status> {
        let Some(id) = req.run_id.as_deref() else {
            return Ok(None);
        };
        if req.pid != 0 {
            return Err(conflicting_target("pid or run_id"));
        }
        let (pid, control) = self.runs.get(id)?.target()?;
        req.pid = pid;
        Ok(Some(control))
    }

    fn run_breakpoint_target(
        &self,
        id: Option<&str>,
        pid: &mut i32,
    ) -> std::result::Result<Option<aidbg::breakpoint::Control>, Status> {
        let Some(id) = id else {
            if *pid > 0 && self.runs.control_for_pid(*pid)?.is_some() {
                return Err(script_error(
                    aidbg::Diagnostic::new(
                        "USE_RUN_ID",
                        "This PID is already controlled by an active run",
                        Some("use run_id"),
                    )
                    .into(),
                ));
            }
            return Ok(None);
        };
        if *pid != 0 {
            return Err(conflicting_target("pid or run_id"));
        }
        let (target, control) = self.runs.get(id)?.target()?;
        *pid = target;
        Ok(Some(control))
    }

    async fn run_code_job<T: serde::Serialize + Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> std::result::Result<Response<DocumentReply>, Status> {
        let permit = Arc::clone(&self.code_engine)
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("an offline code operation is already running")
            })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            document(job().map_err(script_error)?)
        })
        .await
        .map_err(internal)?
    }
}

fn address_mappable(address: usize) -> Option<bool> {
    let size = usize::try_from(unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) }).ok()?;
    let mapped = unsafe {
        nix::libc::mmap(
            address as *mut _,
            size,
            nix::libc::PROT_NONE,
            nix::libc::MAP_PRIVATE | nix::libc::MAP_ANONYMOUS | nix::libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if mapped == nix::libc::MAP_FAILED {
        return match nix::errno::Errno::last() {
            nix::errno::Errno::EEXIST => Some(true),
            nix::errno::Errno::ENOMEM => Some(false),
            _ => None,
        };
    }
    unsafe { nix::libc::munmap(mapped, size) };
    Some(mapped as usize == address)
}

fn user_va_bits() -> Option<u32> {
    let widths: &[u32] = if cfg!(target_arch = "aarch64") {
        &[52, 48, 47, 42, 39, 36]
    } else {
        &[56, 47]
    };
    widths
        .iter()
        .copied()
        .find(|bits| address_mappable(3 << (*bits - 2)) == Some(true))
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
    private_directory(&args.state_dir)?;
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
            private_directory(
                path.parent()
                    .ok_or_else(|| io::Error::other("socket parent is missing"))?,
            )?;
            let listener = UnixListener::bind(&path)?;
            let metadata = fs::symlink_metadata(&path)?;
            let socket = Socket {
                path,
                identity: (metadata.dev(), metadata.ino()),
            };
            fs::set_permissions(&socket.path, Permissions::from_mode(0o600))?;
            Ok((listener, socket))
        })
        .transpose()?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let overrides = Arc::new(aidbg::symbols::Overrides::open(&args.state_dir)?);
    let dump_store = Arc::new(DumpStore::open(
        &args.state_dir,
        args.coredump_retention_secs,
        u64::from(args.coredump_max_mib) * 1024 * 1024,
    )?);
    let janitor = Arc::downgrade(&dump_store);
    let cleanup_interval = std::time::Duration::from_secs(args.coredump_retention_secs.min(60));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(cleanup_interval).await;
            let Some(store) = janitor.upgrade() else {
                break;
            };
            let _ = tokio::task::spawn_blocking(move || store.prune()).await;
        }
    });
    let target_policy = Arc::new(target_policy::Policy::open(
        &args.state_dir,
        args.target_call_policy.as_deref(),
    )?);
    let store = Arc::new(Store(args.state_dir));
    let (breakpoints, saver) = Breakpoints::new(Arc::clone(&store))?;
    let service = Service {
        scripts: Arc::new(Scripts::remote(args.max_open_cores)),
        script_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        run_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        runs: Arc::default(),
        store,
        breakpoints: breakpoints.clone(),
        capture_lock: Arc::new(Mutex::new(())),
        profiler: Arc::new(tokio::sync::Semaphore::new(1)),
        overrides,
        code_engine: Arc::new(tokio::sync::Semaphore::new(1)),
        target_policy,
        coredumps: Arc::new(tokio::sync::Semaphore::new(1)),
        dump_store,
    };
    let service = Arc::new(service);
    let router = || {
        Server::builder().add_service(
            DebuggerServer::from_arc(service.clone())
                .max_decoding_message_size(MAX_RPC)
                .max_encoding_message_size(MAX_RPC),
        )
    };
    let (shutdown, signal) = tokio::sync::watch::channel(false);
    let monitor = tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
        let _ = shutdown.send(true);
    });
    let wait = |mut signal: tokio::sync::watch::Receiver<bool>| async move {
        let _ = signal.wait_for(|stop| *stop).await;
    };
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
    drop(service);
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
