use aidbg::{Result, rpc, script};
use clap::Args;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::RwLock,
};

#[derive(Args)]
pub(super) struct ApiArgs {
    #[arg(long, value_enum, default_value = "offline")]
    mode: script::Mode,
}

#[derive(Args)]
pub(super) struct CheckArgs {
    #[arg(long)]
    source: PathBuf,
    #[arg(long, value_enum, default_value = "offline")]
    mode: script::Mode,
    #[command(flatten)]
    target: TargetArgs,
}

#[derive(Args)]
pub(super) struct RunArgs {
    #[arg(long)]
    timeout_ms: Option<u32>,
    #[arg(long, conflicts_with_all = ["target_id", "core"])]
    run_id: Option<String>,
    #[arg(long)]
    source: PathBuf,
    #[command(flatten)]
    target: TargetArgs,
}

#[derive(Args)]
struct TargetArgs {
    #[arg(long, conflicts_with = "core")]
    target_id: Option<String>,
    #[arg(long)]
    core: Option<PathBuf>,
    #[command(flatten)]
    symbols: SymbolArgs,
}

#[derive(Args)]
struct SymbolArgs {
    #[arg(long)]
    executable: Option<PathBuf>,
    #[arg(long, requires = "executable")]
    debug_symbols: Option<PathBuf>,
}

impl From<SymbolArgs> for script::CoreSymbols {
    fn from(args: SymbolArgs) -> Self {
        Self {
            executable: args.executable,
            debug_symbols: args.debug_symbols,
        }
    }
}

#[derive(Args)]
pub(super) struct OpenArgs {
    #[arg(long, required_unless_present = "path", conflicts_with = "path")]
    dump_id: Option<String>,
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long, requires = "path")]
    upload: bool,
    #[command(flatten)]
    symbols: SymbolArgs,
}

#[derive(Args)]
pub(super) struct CloseArgs {
    #[arg(long)]
    target_id: String,
}

pub(super) struct Client {
    remote: RwLock<Option<rpc::Client>>,
    #[cfg(target_os = "linux")]
    local: Arc<script::Scripts>,
}

impl Client {
    pub fn new(remote: Option<rpc::Client>) -> Self {
        Self {
            remote: RwLock::new(remote),
            #[cfg(target_os = "linux")]
            local: Arc::new(script::Scripts::default()),
        }
    }

    pub fn remote(&self) -> Result<rpc::Client> {
        self.remote
            .read()
            .map_err(|_| io::Error::other("server connection state is unavailable"))?
            .clone()
            .ok_or_else(|| {
                aidbg::Diagnostic::new(
                    "NOT_CONNECTED",
                    "No server connection. Call the connect tool first.",
                    Some("Call connect with the server socket or endpoint."),
                )
                .into()
            })
    }

    pub fn set_remote(&self, client: rpc::Client) -> Result<()> {
        *self
            .remote
            .write()
            .map_err(|_| io::Error::other("server connection state is unavailable"))? =
            Some(client);
        Ok(())
    }

    pub(super) async fn symbols(&self, request: rpc::SearchSymbolsRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request
            .target_id
            .as_deref()
            .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.symbols(request)).await;
        }
        decode(
            self.remote()?
                .search_symbols(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn inspect(&self, request: rpc::InspectRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request
            .target_id
            .as_deref()
            .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.inspect_core(request)).await;
        }
        decode(self.remote()?.inspect(tonic::Request::new(request)).await?)
    }

    pub(super) async fn resolve(&self, request: rpc::ResolveAddressRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request
            .target_id
            .as_deref()
            .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.resolve(request)).await;
        }
        decode(
            self.remote()?
                .resolve_address(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn disassemble(&self, request: rpc::DisassembleRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request
            .target_id
            .as_deref()
            .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.disassemble(request)).await;
        }
        decode(
            self.remote()?
                .disassemble(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn search_memory(&self, request: rpc::SearchMemoryRequest) -> Result<Value> {
        let choices = usize::from(!request.target_id.is_empty())
            + usize::from(request.pid.is_some())
            + usize::from(request.run_id.is_some());
        if choices != 1 {
            return Err(aidbg::Diagnostic::new(
                if choices > 1 {
                    "CONFLICTING_TARGET"
                } else {
                    "INVALID_ARGUMENT"
                },
                "Specify one of target_id, pid or run_id",
                None,
            )
            .into());
        }
        #[cfg(target_os = "linux")]
        if !request.target_id.is_empty() && !remote_target(&request.target_id) {
            let local = self.local.clone();
            return task(move || local.search_memory(request)).await;
        }
        decode(
            self.remote()?
                .search_memory(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn read_memory(&self, request: rpc::ReadMemoryRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request.pid.is_none()
            && request.run_id.is_none()
            && request
                .target_id
                .as_deref()
                .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.read_memory(request)).await;
        }
        decode(
            self.remote()?
                .read_memory(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn observe_threads(
        &self,
        request: aidbg::script_observation::Request,
    ) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request.pid.is_none()
            && request.run_id.is_none()
            && request
                .target_id
                .as_deref()
                .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.observe_threads(request)).await;
        }
        decode(
            self.remote()?
                .observe_threads(tonic::Request::new(encode(request)?))
                .await?,
        )
    }

    pub(super) async fn pointer_chain(&self, request: rpc::PointerChainRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if !remote_target(&request.target_id) {
            let local = self.local.clone();
            return task(move || local.pointer_chain(request)).await;
        }
        decode(
            self.remote()?
                .pointer_chain(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn patch(&self, request: rpc::PatchRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request
            .target_id
            .as_deref()
            .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.patch(request)).await;
        }
        decode(
            self.remote()?
                .plan_patch(tonic::Request::new(request))
                .await?,
        )
    }

    pub(super) async fn emulate(&self, request: rpc::EmulateRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if request
            .target_id
            .as_deref()
            .is_some_and(|id| !remote_target(id))
        {
            let local = self.local.clone();
            return task(move || local.emulate(request)).await;
        }
        decode(self.remote()?.emulate(tonic::Request::new(request)).await?)
    }

    pub async fn api(&self, request: script::ApiRequest) -> Result<Value> {
        Ok(serde_json::to_value(script::api(request)?)?)
    }

    pub async fn check(&self, request: script::CheckRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if !request.target_id.as_deref().is_some_and(remote_target) {
            let local = self.local.clone();
            return task(move || local.check(request)).await;
        }
        decode(self.remote()?.script_check(encode(request)?).await?)
    }

    pub async fn run(&self, request: script::RunRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if let (Some(target_id), None) = (&request.target_id, &request.run_id)
            && !remote_target(target_id)
        {
            let local = self.local.clone();
            return task(move || local.run(request)).await;
        }
        decode(self.remote()?.script_run(encode(request)?).await?)
    }

    pub async fn open(&self, request: script::OpenRequest) -> Result<Value> {
        match (request.path, request.dump_id) {
            #[cfg(target_os = "linux")]
            (Some(path), None) if !request.upload => {
                let local = self.local.clone();
                let mut opened: Value = task(move || local.open(&path, request.symbols)).await?;
                opened["analysis_host"] = "client".into();
                Ok(opened)
            }
            (Some(path), None) => {
                use rpc::artifact_header::Kind;
                let client = self.remote()?;
                let uploaded =
                    super::coredump_client::upload_file(client.clone(), &path, Kind::Core).await?;
                let mut symbols = request.symbols;
                for (path, kind) in [
                    (&mut symbols.executable, Kind::Executable),
                    (&mut symbols.debug_symbols, Kind::DebugSymbols),
                ] {
                    if let Some(local) = path.take() {
                        let uploaded =
                            super::coredump_client::upload_file(client.clone(), &local, kind)
                                .await?;
                        *path = uploaded["server_path"].as_str().map(PathBuf::from);
                    }
                }
                let dump_id = uploaded["dump_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| io::Error::other("uploaded core was not retained"))?;
                let reply = client
                    .clone()
                    .core_open(encode(script::OpenRequest {
                        path: None,
                        dump_id: Some(dump_id.clone()),
                        symbols,
                        upload: false,
                    })?)
                    .await?;
                let mut opened: Value = decode(reply)?;
                opened["dump_id"] = dump_id.into();
                opened["analysis_host"] = "server".into();
                Ok(opened)
            }
            (None, Some(dump_id)) => {
                let request = script::OpenRequest {
                    path: None,
                    dump_id: Some(dump_id.clone()),
                    symbols: request.symbols,
                    upload: false,
                };
                let mut opened: Value = decode(self.remote()?.core_open(encode(request)?).await?)?;
                opened["analysis_host"] = "server".into();
                opened["dump_id"] = dump_id.into();
                Ok(opened)
            }
            _ => Err(io::Error::other("specify a local path or a retained server dump_id").into()),
        }
    }

    pub async fn close(&self, request: script::CloseRequest) -> Result<Value> {
        #[cfg(target_os = "linux")]
        if !remote_target(&request.target_id) {
            return self.local.close(&request.target_id);
        }
        decode(self.remote()?.core_close(encode(request)?).await?)
    }

    async fn cli_target(&self, target: TargetArgs) -> Result<Option<String>> {
        if let Some(path) = target.core {
            let info = self
                .open(script::OpenRequest {
                    path: Some(path),
                    dump_id: None,
                    upload: false,
                    symbols: target.symbols.into(),
                })
                .await?;
            return Ok(info["target_id"].as_str().map(str::to_owned));
        }
        if target.symbols.executable.is_some() {
            return Err(io::Error::other("--executable requires --core").into());
        }
        Ok(target.target_id)
    }
}

pub(super) async fn cli(command: super::Command, remote: Option<rpc::Client>) -> Result<ExitCode> {
    let use_remote = remote.is_some();
    let client = Client::new(remote);
    let response = match command {
        super::Command::ScriptApi(args) => {
            let request = script::ApiRequest { mode: args.mode };
            if use_remote {
                decode(client.remote()?.script_api(encode(request)?).await?)?
            } else {
                client.api(request).await?
            }
        }
        super::Command::ScriptCheck(args) => {
            let source = read_source(&args.source)?;
            let target_id = client.cli_target(args.target).await?;
            let request = script::CheckRequest {
                source,
                mode: args.mode,
                target_id,
            };
            if use_remote && request.target_id.is_none() {
                decode(client.remote()?.script_check(encode(request)?).await?)?
            } else {
                client.check(request).await?
            }
        }
        super::Command::ScriptRun(args) => {
            let source = read_source(&args.source)?;
            let target_id = client.cli_target(args.target).await?;
            if target_id.is_none() && args.run_id.is_none() {
                return Err(io::Error::other(
                    "script-run requires --target-id, --core, or --run-id",
                )
                .into());
            }
            client
                .run(script::RunRequest {
                    source,
                    target_id,
                    run_id: args.run_id,
                    timeout_ms: args.timeout_ms,
                    replay_points: Vec::new(),
                })
                .await?
        }
        super::Command::CoreOpen(args) => {
            client
                .open(script::OpenRequest {
                    path: args.path,
                    dump_id: args.dump_id,
                    symbols: args.symbols.into(),
                    upload: args.upload,
                })
                .await?
        }
        super::Command::CoreClose(args) => {
            client
                .close(script::CloseRequest {
                    target_id: args.target_id,
                })
                .await?
        }
        super::Command::ReadMemory(args) => client.read_memory(args.message()?).await?,
        _ => unreachable!(),
    };
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, &response)?;
    writeln!(out)?;
    Ok(if response["status"] == "failed" {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[cfg(target_os = "linux")]
fn remote_target(id: &str) -> bool {
    id.starts_with("remote-core-")
}

pub(super) fn read_source(path: &Path) -> Result<String> {
    let mut source = String::new();
    if path == Path::new("-") {
        io::stdin().lock().take(65537).read_to_string(&mut source)?;
    } else {
        File::open(path)?.take(65537).read_to_string(&mut source)?;
    }
    if source.len() > 65536 {
        return Err(io::Error::other("script source exceeds 64 KiB").into());
    }
    Ok(source)
}

fn encode(value: impl Serialize) -> Result<rpc::ScriptDocumentRequest> {
    Ok(rpc::ScriptDocumentRequest {
        json: serde_json::to_vec(&value)?,
    })
}

fn decode<T: DeserializeOwned>(response: tonic::Response<rpc::DocumentReply>) -> Result<T> {
    Ok(serde_json::from_slice(&response.into_inner().json)?)
}

#[cfg(target_os = "linux")]
async fn task<T: Serialize + Send + 'static>(
    task: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<Value> {
    Ok(serde_json::to_value(
        tokio::task::spawn_blocking(task).await??,
    )?)
}
