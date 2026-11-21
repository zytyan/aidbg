use aidbg::rpc::{
    self, BreakpointCapabilitiesRequest, BreakpointEventsRequest, BreakpointKind, CaptureScope,
    Client, CoreMode, CoredumpRequest, DisassembleRequest, DocumentReply, FreezeMode,
    InstallBreakpointRequest, QuerySnapshotRequest, RemoveBreakpointRequest, ResolveAddressRequest,
    SearchSymbolsRequest, SnapshotReply, SnapshotRequest, SymbolLocation, SymbolMatch,
    coredump_chunk::Part, install_breakpoint_request,
};
use aidbg::{Result as AidbgResult, selection::requested};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tonic::Request;

#[derive(Parser)]
#[command(about = "Connect to an aidbg debugger server")]
struct Cli {
    #[arg(long)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture a live snapshot or look up a saved snapshot.
    Snapshot(SnapshotArgs),
    /// Save a compressed Linux ELF core from a live process.
    Coredump(CoredumpArgs),
    /// Manage execution breakpoints, hardware watchpoints and their hit events.
    #[command(subcommand)]
    Breakpoint(BreakpointCommand),
    /// Search ELF symbols in a running process.
    Symbols(SymbolArgs),
    /// Resolve a runtime address to its module, ELF address and symbol.
    Resolve(ResolveArgs),
    /// Decode instructions around a runtime address.
    Disassemble(DisassembleArgs),
    /// Expose debugger tools over MCP stdio.
    Mcp,
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
struct CoredumpArgs {
    #[arg(long)]
    pid: i32,
    /// Memory coverage of the dump.
    #[arg(long, value_enum, default_value = "stack")]
    #[serde(default)]
    mode: DumpMode,
    /// New client-side .core.zst path.
    #[arg(long)]
    output: PathBuf,
    /// Time limit for freezing the target and reading its memory, in milliseconds.
    #[arg(long)]
    timeout_ms: Option<u32>,
    /// Server capture-buffer budget in MiB. Zero uses file staging.
    #[arg(long)]
    buffer_mib: Option<u32>,
    /// Server memory-read block size in KiB.
    #[arg(long)]
    block_kib: Option<u32>,
}

async fn save_coredump(mut client: Client, args: CoredumpArgs) -> AidbgResult<Value> {
    if std::fs::symlink_metadata(&args.output).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "coredump output already exists",
        )
        .into());
    }
    let parent = args
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file = tempfile::NamedTempFile::new_in(parent)?;
    let mut writer = tokio::fs::File::from_std(file.reopen()?);
    let mut stream = client
        .coredump(Request::new(CoredumpRequest {
            pid: args.pid,
            mode: CoreMode::from(args.mode) as i32,
            timeout_ms: args.timeout_ms,
            buffer_mib: args.buffer_mib,
            block_kib: args.block_kib,
        }))
        .await?
        .into_inner();
    let mut summary = None;
    let mut size = 0_u64;
    while let Some(chunk) = stream.message().await? {
        match chunk.part {
            Some(Part::Data(data)) if summary.is_none() => {
                writer.write_all(&data).await?;
                size += data.len() as u64;
            }
            Some(Part::SummaryJson(json)) if summary.is_none() => {
                summary = Some(serde_json::from_slice::<Value>(&json)?);
            }
            _ => return Err(io::Error::other("invalid coredump stream").into()),
        }
    }
    let mut summary = summary
        .filter(|doc| {
            size > 0
                && doc["compressed_bytes"].as_u64() == Some(size)
                && matches!(doc["status"].as_str(), Some("complete" | "partial"))
        })
        .ok_or_else(|| io::Error::other("coredump stream ended without a valid summary"))?;
    writer.flush().await?;
    writer.sync_all().await?;
    drop(writer);
    file.persist_noclobber(&args.output)?;
    summary["path"] = Value::String(args.output.to_string_lossy().into_owned());
    Ok(summary)
}

#[derive(Subcommand)]
enum BreakpointCommand {
    Set(BreakpointArgs),
    Remove(RemoveArgs),
    Events(EventsArgs),
    Capabilities,
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum RuleKind {
    #[default]
    Hardware,
    Software,
    Write,
    ReadWrite,
}

#[derive(Args, Deserialize, JsonSchema)]
struct BreakpointArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long, value_enum, default_value = "hardware")]
    #[serde(default)]
    kind: RuleKind,
    /// Watch width in bytes (required for hardware watchpoints).
    #[arg(long)]
    length: Option<u32>,
    /// Absolute runtime address in decimal or 0x-prefixed hex.
    #[arg(long, conflicts_with_all = ["module", "symbol", "instance"])]
    address: Option<String>,
    /// Exact path, basename or build ID of the loaded module.
    #[arg(long, requires = "symbol")]
    module: Option<String>,
    /// Exact ELF symbol name.
    #[arg(long, requires = "module")]
    symbol: Option<String>,
    /// Runtime base of the module instance, as shown in symbols output.
    #[arg(long, requires = "module")]
    instance: Option<String>,
    /// Freeze all threads for a process-wide snapshot.
    #[arg(long)]
    #[serde(default)]
    all_threads: bool,
    /// Callback budget in milliseconds (1–500, default 100).
    #[arg(long)]
    timeout_ms: Option<u32>,
}

impl BreakpointArgs {
    fn message(self) -> AidbgResult<InstallBreakpointRequest> {
        use install_breakpoint_request::Location;
        let location = match (self.address, self.module, self.symbol, self.instance) {
            (Some(address), None, None, None) => Location::Address(parse_address(&address)?),
            (None, Some(module), Some(symbol), instance) => Location::Symbol(SymbolLocation {
                module,
                symbol,
                instance: instance.as_deref().map(parse_address).transpose()?,
            }),
            _ => {
                return Err(
                    io::Error::other("provide --address or both --module and --symbol").into(),
                );
            }
        };
        Ok(InstallBreakpointRequest {
            pid: self.pid,
            location: Some(location),
            scope: if self.all_threads {
                CaptureScope::Process
            } else {
                CaptureScope::Thread
            } as i32,
            timeout_ms: self.timeout_ms,
            kind: match self.kind {
                RuleKind::Hardware => BreakpointKind::Hardware,
                RuleKind::Software => BreakpointKind::Software,
                RuleKind::Write => BreakpointKind::Write,
                RuleKind::ReadWrite => BreakpointKind::ReadWrite,
            } as i32,
            length: self.length,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct RemoveArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    breakpoint_id: u64,
}

#[derive(Args, Deserialize, JsonSchema)]
struct EventsArgs {
    #[arg(long)]
    breakpoint_id: Option<u64>,
    #[arg(long, default_value_t)]
    #[serde(default)]
    after_event_id: u64,
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum MatchMode {
    #[default]
    Exact,
    Glob,
    Regex,
}

#[derive(Args, Deserialize, JsonSchema)]
struct SymbolArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    pattern: String,
    #[arg(long, value_enum, default_value = "exact")]
    #[serde(default)]
    mode: MatchMode,
    #[arg(long)]
    module: Option<String>,
    #[arg(long)]
    limit: Option<u32>,
}

impl SymbolArgs {
    fn message(self) -> SearchSymbolsRequest {
        SearchSymbolsRequest {
            pid: self.pid,
            pattern: self.pattern,
            match_mode: match self.mode {
                MatchMode::Exact => SymbolMatch::Exact,
                MatchMode::Glob => SymbolMatch::Glob,
                MatchMode::Regex => SymbolMatch::Regex,
            } as i32,
            module: self.module,
            limit: self.limit,
        }
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct ResolveArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    address: String,
}

#[derive(Args, Deserialize, JsonSchema)]
struct DisassembleArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    address: String,
    #[arg(long)]
    before: Option<u32>,
    #[arg(long)]
    after: Option<u32>,
    /// Known instruction boundary in the same executable mapping.
    #[arg(long)]
    start: Option<String>,
}

impl DisassembleArgs {
    fn message(self) -> AidbgResult<DisassembleRequest> {
        Ok(DisassembleRequest {
            pid: self.pid,
            address: parse_address(&self.address)?,
            before: self.before,
            after: self.after,
            start: self.start.as_deref().map(parse_address).transpose()?,
        })
    }
}

fn parse_address(value: &str) -> AidbgResult<u64> {
    Ok(
        match value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16)?,
            None => value.parse()?,
        },
    )
}

#[derive(Args)]
struct SnapshotArgs {
    #[arg(long, required_unless_present_any = ["from", "event"], conflicts_with_all = ["from", "event"])]
    pid: Option<i32>,
    /// Query this saved snapshot ID instead of capturing a PID.
    #[arg(long)]
    from: Option<String>,
    /// Query the snapshot saved for this breakpoint event ID.
    #[arg(long, conflicts_with = "from")]
    event: Option<u64>,
    #[arg(long, requires = "pid", value_enum)]
    freeze: Option<Freeze>,
    /// Select comma-separated fields. Use dots to select nested fields.
    #[arg(long, value_delimiter = ',')]
    fields: Vec<String>,
    #[arg(long)]
    tid: Option<i32>,
    /// Show at most this many frames per thread.
    #[arg(long)]
    frames: Option<u32>,
    /// Export the full snapshot to a new local file.
    #[arg(long)]
    save: Option<PathBuf>,
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum Freeze {
    #[default]
    Try,
    Never,
    Required,
}

impl From<Freeze> for FreezeMode {
    fn from(value: Freeze) -> Self {
        match value {
            Freeze::Try => Self::Try,
            Freeze::Never => Self::Never,
            Freeze::Required => Self::Required,
        }
    }
}

fn request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.set_timeout(Duration::from_secs(15));
    request
}

fn save_local(path: &Path, bytes: &[u8]) -> AidbgResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)?;
    Ok(())
}

async fn snapshot_cli(mut client: Client, args: SnapshotArgs) -> AidbgResult<ExitCode> {
    let selection = requested(args.fields, args.tid, args.frames);
    let filtered = selection.is_some();
    let reply = if args.from.is_some() || args.event.is_some() {
        client
            .query_snapshot(request(QuerySnapshotRequest {
                snapshot_id: args.from.unwrap_or_default(),
                event_id: args.event,
                selection,
            }))
            .await?
    } else {
        let mode = FreezeMode::from(args.freeze.unwrap_or_default());
        let pid = args
            .pid
            .ok_or_else(|| io::Error::other("expected --pid, --from or --event"))?;
        client
            .snapshot(request(SnapshotRequest {
                pid,
                freeze: mode as i32,
                selection,
            }))
            .await?
    }
    .into_inner();
    if let Some(path) = args.save {
        if filtered {
            let full = client
                .query_snapshot(request(QuerySnapshotRequest {
                    snapshot_id: reply.snapshot_id.clone(),
                    event_id: None,
                    selection: None,
                }))
                .await?
                .into_inner();
            save_local(&path, &full.snapshot_json)?;
        } else {
            save_local(&path, &reply.snapshot_json)?;
        }
    }
    let doc: Value = serde_json::from_slice(&reply.snapshot_json)?;
    let mut out = io::stdout().lock();
    out.write_all(&reply.snapshot_json)?;
    writeln!(out)?;
    out.flush()?;
    Ok(
        if matches!(doc["status"].as_str(), Some("failed" | "timed_out")) {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        },
    )
}

#[derive(Deserialize, JsonSchema)]
struct CaptureTool {
    /// PID on the Linux host where aidbg-server is running.
    pid: i32,
    #[serde(default)]
    freeze: Freeze,
    #[serde(default)]
    fields: Vec<String>,
    tid: Option<i32>,
    frames: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct QueryTool {
    snapshot_id: Option<String>,
    event_id: Option<u64>,
    #[serde(default)]
    fields: Vec<String>,
    tid: Option<i32>,
    frames: Option<u32>,
}

struct Mcp {
    client: Client,
}

fn tool_reply(
    result: std::result::Result<tonic::Response<SnapshotReply>, tonic::Status>,
) -> CallToolResult {
    tool_document(result.map(|reply| reply.into_inner().snapshot_json))
}

fn tool_document(result: std::result::Result<Vec<u8>, tonic::Status>) -> CallToolResult {
    match result {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(doc)
                if matches!(
                    doc["status"].as_str(),
                    Some("failed" | "timed_out" | "cleanup_failed")
                ) =>
            {
                CallToolResult::structured_error(doc)
            }
            Ok(doc) => CallToolResult::structured(doc),
            Err(e) => CallToolResult::structured_error(serde_json::json!({"error":e.to_string()})),
        },
        Err(e) => CallToolResult::structured_error(serde_json::json!({"error":e.message()})),
    }
}

fn document_tool(
    result: std::result::Result<tonic::Response<DocumentReply>, tonic::Status>,
) -> CallToolResult {
    tool_document(result.map(|reply| reply.into_inner().json))
}

fn argument_error(error: impl ToString) -> CallToolResult {
    CallToolResult::structured_error(serde_json::json!({"error": error.to_string()}))
}

#[tool_router(server_handler)]
impl Mcp {
    #[tool(
        description = "Save a compressed Linux ELF core to a new client-side path. Modes are lite, stack-4k, stack, standard, extended, and full. Returns coverage and output metadata."
    )]
    async fn coredump(&self, Parameters(args): Parameters<CoredumpArgs>) -> CallToolResult {
        match save_coredump(self.client.clone(), args).await {
            Ok(summary) => CallToolResult::structured(summary),
            Err(error) => argument_error(error),
        }
    }

    #[tool(
        description = "Capture and save a process snapshot. Optional dotted fields, tid, and frames filter the response."
    )]
    async fn snapshot(&self, Parameters(args): Parameters<CaptureTool>) -> CallToolResult {
        tool_reply(
            self.client
                .clone()
                .snapshot(request(SnapshotRequest {
                    pid: args.pid,
                    freeze: FreezeMode::from(args.freeze) as i32,
                    selection: requested(args.fields, args.tid, args.frames),
                }))
                .await,
        )
    }

    #[tool(description = "Query a saved snapshot by snapshot_id or breakpoint event_id.")]
    async fn snapshot_query(&self, Parameters(args): Parameters<QueryTool>) -> CallToolResult {
        tool_reply(
            self.client
                .clone()
                .query_snapshot(request(QuerySnapshotRequest {
                    snapshot_id: args.snapshot_id.unwrap_or_default(),
                    event_id: args.event_id,
                    selection: requested(args.fields, args.tid, args.frames),
                }))
                .await,
        )
    }
    #[tool(
        description = "Install an execution breakpoint or hardware watchpoint with an automatic snapshot callback."
    )]
    async fn breakpoint_set(&self, Parameters(args): Parameters<BreakpointArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(
                self.client
                    .clone()
                    .install_breakpoint(request(message))
                    .await,
            ),
            Err(e) => argument_error(e),
        }
    }

    #[tool(description = "Remove a breakpoint or watchpoint from the server.")]
    async fn breakpoint_remove(&self, Parameters(args): Parameters<RemoveArgs>) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .remove_breakpoint(request(RemoveBreakpointRequest {
                    pid: args.pid,
                    breakpoint_id: args.breakpoint_id,
                }))
                .await,
        )
    }

    #[tool(
        description = "Read recent breakpoint and watchpoint hits and their saved snapshot IDs."
    )]
    async fn breakpoint_events(&self, Parameters(args): Parameters<EventsArgs>) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .breakpoint_events(request(BreakpointEventsRequest {
                    breakpoint_id: args.breakpoint_id,
                    after_event_id: args.after_event_id,
                }))
                .await,
        )
    }

    #[tool(description = "Search ELF symbols in a running process by exact name, glob or regex.")]
    async fn symbols(&self, Parameters(args): Parameters<SymbolArgs>) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .search_symbols(request(args.message()))
                .await,
        )
    }

    #[tool(
        description = "Resolve a runtime address to its loaded module instance, ELF address and symbol."
    )]
    async fn resolve_address(&self, Parameters(args): Parameters<ResolveArgs>) -> CallToolResult {
        match parse_address(&args.address) {
            Ok(address) => document_tool(
                self.client
                    .clone()
                    .resolve_address(request(ResolveAddressRequest {
                        pid: args.pid,
                        address,
                    }))
                    .await,
            ),
            Err(e) => argument_error(e),
        }
    }
    #[tool(
        description = "Report the supported breakpoint modes, watch widths, alignment and hardware slots."
    )]
    async fn breakpoint_capabilities(&self) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .breakpoint_capabilities(request(BreakpointCapabilitiesRequest {}))
                .await,
        )
    }

    #[tool(description = "Decode an instruction window around a runtime address using Capstone.")]
    async fn disassemble(&self, Parameters(args): Parameters<DisassembleArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().disassemble(request(message)).await),
            Err(e) => argument_error(e),
        }
    }
}

#[tokio::main]
async fn main() -> AidbgResult<ExitCode> {
    let cli = Cli::parse();
    let mut client = rpc::connect(&cli.socket).await?;
    let reply = match cli.command {
        Command::Snapshot(args) => return snapshot_cli(client, args).await,
        Command::Coredump(args) => {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let summary = tokio::select! {
                result = save_coredump(client, args) => result?,
                result = tokio::signal::ctrl_c() => {
                    result?;
                    return Ok(ExitCode::from(130));
                }
                _ = terminate.recv() => return Ok(ExitCode::from(143)),
            };
            let mut out = io::stdout().lock();
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
            out.flush()?;
            return Ok(ExitCode::SUCCESS);
        }
        Command::Breakpoint(command) => match command {
            BreakpointCommand::Set(args) => {
                client.install_breakpoint(request(args.message()?)).await?
            }
            BreakpointCommand::Remove(args) => {
                client
                    .remove_breakpoint(request(RemoveBreakpointRequest {
                        pid: args.pid,
                        breakpoint_id: args.breakpoint_id,
                    }))
                    .await?
            }
            BreakpointCommand::Capabilities => {
                client
                    .breakpoint_capabilities(request(BreakpointCapabilitiesRequest {}))
                    .await?
            }
            BreakpointCommand::Events(args) => {
                client
                    .breakpoint_events(request(BreakpointEventsRequest {
                        breakpoint_id: args.breakpoint_id,
                        after_event_id: args.after_event_id,
                    }))
                    .await?
            }
        },
        Command::Symbols(args) => client.search_symbols(request(args.message())).await?,
        Command::Resolve(args) => {
            client
                .resolve_address(request(ResolveAddressRequest {
                    pid: args.pid,
                    address: parse_address(&args.address)?,
                }))
                .await?
        }
        Command::Disassemble(args) => client.disassemble(request(args.message()?)).await?,
        Command::Mcp => {
            let mcp = Mcp { client }.serve(rmcp::transport::stdio()).await?;
            mcp.waiting().await?;
            return Ok(ExitCode::SUCCESS);
        }
    }
    .into_inner();
    let doc: Value = serde_json::from_slice(&reply.json)?;
    let mut out = io::stdout().lock();
    out.write_all(&reply.json)?;
    writeln!(out)?;
    out.flush()?;
    Ok(if doc["status"] == "cleanup_failed" {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}
