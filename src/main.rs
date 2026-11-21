#[path = "coredump/client.rs"]
mod coredump_client;

use aidbg::rpc::{
    self, AddressRange, AssembleRequest, BreakpointCapabilitiesRequest, BreakpointEventsRequest,
    BreakpointKind, CaptureScope, Client, DisassembleRequest, DocumentReply, EmulateRequest,
    FreezeMode, InspectRequest, InstallBreakpointRequest, MemoryCopy, ObjectProbe, PatchRequest,
    ProfileRequest, QuerySnapshotRequest, RemoveBreakpointRequest, ResolveAddressRequest,
    SearchSymbolsRequest, SetSymbolOverride, SnapshotReply, SnapshotRequest, StepWatchRequest,
    SymbolLocation, SymbolMatch, SymbolOverrideRequest, TargetCallRequest,
    install_breakpoint_request, symbol_override_request::Action as OverrideAction,
};
use aidbg::{Result as AidbgResult, selection::requested};
use clap::{Args, Parser, Subcommand, ValueEnum};
use coredump_client::{CoredumpArgs, save_coredump};
use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
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
    /// Track value changes within a bounded single-step window.
    WatchStep(WatchStepArgs),
    /// Invoke a native scalar function using an explicit scratch stack and step budget.
    TargetCall(TargetCallArgs),
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
    /// Sample user-space PCs or recover a call tree from sampled stacks.
    Perf(PerfArgs),
    /// Manage debugger-local symbol names and ranges.
    #[command(subcommand)]
    SymbolOverride(SymbolOverrideCommand),
    /// Read a C/C++ variable, member, subscript or dereference from DWARF.
    Inspect(InspectArgs),
    /// Assemble instructions for the architecture running the server.
    #[command(name = "asm")]
    Assemble(AssembleArgs),
    /// Create an offline patch within an original instruction window.
    Patch(PatchArgs),
    /// Emulate an offline code and memory copy from a JSON file.
    Emulate(EmulateFile),
    /// Expose debugger tools over MCP stdio.
    Mcp,
}

#[derive(Args, Deserialize, JsonSchema)]
struct WatchStepArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    tid: Option<i32>,
    #[arg(long)]
    address: String,
    #[arg(long)]
    length: u32,
    #[arg(long)]
    pc_start: String,
    #[arg(long)]
    pc_end: String,
    #[arg(long)]
    max_steps: Option<u32>,
    #[arg(long)]
    timeout_ms: Option<u32>,
}

impl WatchStepArgs {
    fn message(self) -> AidbgResult<StepWatchRequest> {
        Ok(StepWatchRequest {
            pid: self.pid,
            tid: self.tid,
            length: self.length,
            max_steps: self.max_steps,
            timeout_ms: self.timeout_ms,
            address: parse_address(&self.address)?,
            pc_start: parse_address(&self.pc_start)?,
            pc_end: parse_address(&self.pc_end)?,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct TargetCallArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    tid: Option<i32>,
    #[arg(long)]
    module: String,
    #[arg(long)]
    symbol: String,
    #[arg(long)]
    instance: Option<String>,
    #[arg(long = "arg")]
    #[serde(default)]
    arguments: Vec<String>,
    #[arg(long)]
    return_type: String,
    #[arg(long)]
    scratch_address: String,
    #[arg(long)]
    scratch_length: u32,
    #[arg(long)]
    max_steps: Option<u32>,
    #[arg(long)]
    timeout_ms: Option<u32>,
    #[arg(long)]
    #[serde(default)]
    allow_side_effects: bool,
}

impl TargetCallArgs {
    fn message(self) -> AidbgResult<TargetCallRequest> {
        Ok(TargetCallRequest {
            pid: self.pid,
            tid: self.tid,
            module: self.module,
            symbol: self.symbol,
            instance: self.instance.as_deref().map(parse_address).transpose()?,
            arguments: self.arguments,
            return_type: self.return_type,
            scratch_address: parse_address(&self.scratch_address)?,
            scratch_length: self.scratch_length,
            max_steps: self.max_steps,
            timeout_ms: self.timeout_ms,
            allow_side_effects: self.allow_side_effects,
        })
    }
}

#[derive(Subcommand)]
enum BreakpointCommand {
    Set(BreakpointArgs),
    Remove(RemoveArgs),
    Events(EventsArgs),
    Capabilities(CapabilityArgs),
}

#[derive(Args, Deserialize, JsonSchema)]
struct CapabilityArgs {
    #[arg(long)]
    pid: Option<i32>,
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

#[derive(Args, Deserialize, JsonSchema)]
struct PerfArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long, conflicts_with = "stack", required_unless_present = "stack")]
    #[serde(default)]
    hotspot: bool,
    #[arg(long)]
    #[serde(default)]
    stack: bool,
    #[arg(long)]
    duration_ms: Option<u32>,
    #[arg(long)]
    frequency_hz: Option<u32>,
    #[arg(long)]
    tid: Option<i32>,
}

impl PerfArgs {
    fn message(self) -> AidbgResult<ProfileRequest> {
        if self.hotspot == self.stack {
            return Err(io::Error::other("select exactly one of hotspot or stack").into());
        }
        Ok(ProfileRequest {
            pid: self.pid,
            stack: self.stack,
            duration_ms: self.duration_ms,
            frequency_hz: self.frequency_hz,
            tid: self.tid,
        })
    }
}

#[derive(Subcommand)]
enum SymbolOverrideCommand {
    Set(OverrideArgs),
    Remove(OverrideId),
    List,
}

#[derive(Args, Deserialize, JsonSchema)]
struct OverrideArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    address: String,
    #[arg(long, default_value_t = 1)]
    #[serde(default = "single_byte")]
    length: u64,
    #[arg(long)]
    name: String,
}

fn single_byte() -> u64 {
    1
}

impl OverrideArgs {
    fn action(self) -> AidbgResult<OverrideAction> {
        Ok(OverrideAction::Set(SetSymbolOverride {
            pid: self.pid,
            address: parse_address(&self.address)?,
            length: self.length,
            name: self.name,
        }))
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct OverrideId {
    #[arg(long)]
    id: String,
}

fn override_request(action: OverrideAction) -> Request<SymbolOverrideRequest> {
    request(SymbolOverrideRequest {
        action: Some(action),
    })
}

#[derive(Args, Deserialize, JsonSchema)]
struct InspectArgs {
    #[arg(long)]
    pid: i32,
    #[arg(long)]
    tid: Option<i32>,
    #[arg(long)]
    expression: String,
    #[arg(long)]
    module: Option<String>,
    #[arg(long)]
    instance: Option<String>,
}

impl InspectArgs {
    fn message(self) -> AidbgResult<InspectRequest> {
        Ok(InspectRequest {
            pid: self.pid,
            tid: self.tid,
            expression: self.expression,
            module: self.module,
            instance: self.instance.as_deref().map(parse_address).transpose()?,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct AssembleArgs {
    #[arg(long)]
    address: String,
    #[arg(long)]
    source: String,
}

impl AssembleArgs {
    fn message(self) -> AidbgResult<AssembleRequest> {
        Ok(AssembleRequest {
            address: parse_address(&self.address)?,
            source: self.source,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct PatchArgs {
    #[arg(long)]
    base: String,
    #[arg(long)]
    address: String,
    /// Original instruction bytes as hexadecimal, starting at the specified base.
    #[arg(long)]
    original: String,
    #[arg(long)]
    source: String,
    /// Existing patch range as ADDRESS:LENGTH. May be repeated.
    #[arg(long)]
    #[serde(default)]
    existing: Vec<String>,
}

fn hex_bytes(input: &str) -> AidbgResult<Vec<u8>> {
    let hex = input.strip_prefix("0x").unwrap_or(input);
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(io::Error::other("expected hexadecimal bytes without separators").into());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&hex[i..i + 2], 16)?))
        .collect()
}

impl PatchArgs {
    fn message(self) -> AidbgResult<PatchRequest> {
        let existing = self
            .existing
            .iter()
            .map(|range| {
                let (address, length) = range
                    .split_once(':')
                    .ok_or_else(|| io::Error::other("expected ADDRESS:LENGTH"))?;
                Ok(AddressRange {
                    address: parse_address(address)?,
                    length: parse_address(length)?,
                })
            })
            .collect::<AidbgResult<_>>()?;
        Ok(PatchRequest {
            base: parse_address(&self.base)?,
            address: parse_address(&self.address)?,
            original: hex_bytes(&self.original)?,
            source: self.source,
            existing,
        })
    }
}

#[derive(Args)]
struct EmulateFile {
    #[arg(long)]
    state: PathBuf,
}

#[derive(Deserialize, JsonSchema)]
struct EmulateArgs {
    address: String,
    code: String,
    #[serde(default)]
    registers: BTreeMap<String, String>,
    #[serde(default)]
    memory: Vec<MemoryArgs>,
    #[serde(default)]
    watch: Vec<RangeArgs>,
    #[serde(default)]
    objects: Vec<ObjectArgs>,
    instruction_limit: Option<u32>,
    timeout_ms: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct MemoryArgs {
    address: String,
    bytes: String,
    #[serde(default)]
    writable: bool,
}

#[derive(Deserialize, JsonSchema)]
struct RangeArgs {
    address: String,
    length: u64,
}

#[derive(Deserialize, JsonSchema)]
struct ObjectArgs {
    name: String,
    address: String,
    length: u64,
    #[serde(default)]
    guard_bytes: u32,
}

impl EmulateArgs {
    fn message(self) -> AidbgResult<EmulateRequest> {
        let registers = self
            .registers
            .into_iter()
            .map(|(name, value)| Ok((name, parse_address(&value)?)))
            .collect::<AidbgResult<_>>()?;
        let memory = self
            .memory
            .into_iter()
            .map(|copy| {
                Ok(MemoryCopy {
                    address: parse_address(&copy.address)?,
                    contents: hex_bytes(&copy.bytes)?,
                    writable: copy.writable,
                })
            })
            .collect::<AidbgResult<_>>()?;
        let watch = self
            .watch
            .into_iter()
            .map(|range| {
                Ok(AddressRange {
                    address: parse_address(&range.address)?,
                    length: range.length,
                })
            })
            .collect::<AidbgResult<_>>()?;
        let objects = self
            .objects
            .into_iter()
            .map(|probe| {
                Ok(ObjectProbe {
                    name: probe.name,
                    address: parse_address(&probe.address)?,
                    length: probe.length,
                    guard_bytes: probe.guard_bytes,
                })
            })
            .collect::<AidbgResult<_>>()?;
        Ok(EmulateRequest {
            address: parse_address(&self.address)?,
            code: hex_bytes(&self.code)?,
            registers,
            memory,
            watch,
            objects,
            instruction_limit: self.instruction_limit,
            timeout_ms: self.timeout_ms,
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
        description = "Save a compressed Linux ELF core to a client-side path. Set resume to true with the original output path to resume a download. Returns the dump ID, coverage, and output metadata."
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
    async fn breakpoint_capabilities(
        &self,
        Parameters(args): Parameters<CapabilityArgs>,
    ) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .breakpoint_capabilities(request(BreakpointCapabilitiesRequest { pid: args.pid }))
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

    #[tool(description = "Sample user-space hotspots or call stacks with Linux perf events.")]
    async fn perf(&self, Parameters(args): Parameters<PerfArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().profile(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(description = "Add a debugger-local symbol name over a loaded module range.")]
    async fn symbol_override_set(
        &self,
        Parameters(args): Parameters<OverrideArgs>,
    ) -> CallToolResult {
        match args.action() {
            Ok(action) => document_tool(
                self.client
                    .clone()
                    .symbol_override(override_request(action))
                    .await,
            ),
            Err(e) => argument_error(e),
        }
    }

    #[tool(description = "Remove a debugger-local symbol override by ID.")]
    async fn symbol_override_remove(
        &self,
        Parameters(args): Parameters<OverrideId>,
    ) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .symbol_override(override_request(OverrideAction::RemoveId(args.id)))
                .await,
        )
    }

    #[tool(description = "List debugger-local symbol overrides and their scopes.")]
    async fn symbol_override_list(&self) -> CallToolResult {
        document_tool(
            self.client
                .clone()
                .symbol_override(override_request(OverrideAction::List(true)))
                .await,
        )
    }

    #[tool(
        description = "Read a DWARF-backed C/C++ variable or read-only access expression in the current frame."
    )]
    async fn inspect(&self, Parameters(args): Parameters<InspectArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().inspect(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Compare a live data range after each step in a bounded user-space PC window."
    )]
    async fn watch_step(&self, Parameters(args): Parameters<WatchStepArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().step_watch(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Call a native scalar function within its symbol range using a dedicated target scratch stack and explicit consent to side effects."
    )]
    async fn target_call(&self, Parameters(args): Parameters<TargetCallArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().target_call(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(description = "Assemble instructions with Keystone for the server architecture.")]
    async fn assemble(&self, Parameters(args): Parameters<AssembleArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().assemble(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Plan an offline patch and check original instruction boundaries with Capstone."
    )]
    async fn plan_patch(&self, Parameters(args): Parameters<PatchArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().plan_patch(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Simulate copied code, registers and memory with Unicorn, with optional watchpoints and object bounds probes."
    )]
    async fn emulate(&self, Parameters(args): Parameters<EmulateArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(self.client.clone().emulate(request(message)).await),
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
            BreakpointCommand::Capabilities(args) => {
                client
                    .breakpoint_capabilities(request(BreakpointCapabilitiesRequest {
                        pid: args.pid,
                    }))
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
        Command::Perf(args) => client.profile(request(args.message()?)).await?,
        Command::Inspect(args) => client.inspect(request(args.message()?)).await?,
        Command::WatchStep(args) => client.step_watch(request(args.message()?)).await?,
        Command::TargetCall(args) => client.target_call(request(args.message()?)).await?,
        Command::Assemble(args) => client.assemble(request(args.message()?)).await?,
        Command::Patch(args) => client.plan_patch(request(args.message()?)).await?,
        Command::Emulate(args) => {
            let bytes = std::fs::read(args.state)?;
            let args: EmulateArgs = serde_json::from_slice(&bytes)?;
            client.emulate(request(args.message()?)).await?
        }
        Command::SymbolOverride(command) => {
            let action = match command {
                SymbolOverrideCommand::Set(args) => args.action()?,
                SymbolOverrideCommand::Remove(args) => OverrideAction::RemoveId(args.id),
                SymbolOverrideCommand::List => OverrideAction::List(true),
            };
            client.symbol_override(override_request(action)).await?
        }
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
    Ok(
        if doc["status"] == "cleanup_failed" || doc["status"] == "unavailable" {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        },
    )
}
