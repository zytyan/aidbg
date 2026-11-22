#[path = "coredump/client.rs"]
mod coredump_client;
#[path = "script/client.rs"]
mod script_client;

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
#[command(about = "Connect to an aidbg debugger server", version = aidbg::BUILD_VERSION)]
struct Cli {
    #[arg(long, conflicts_with = "endpoint")]
    socket: Option<PathBuf>,
    /// HTTP endpoint of the Linux server or an SSH forwarding address.
    #[arg(long)]
    endpoint: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show TypeScript declarations and an example.
    ScriptApi(script_client::ApiArgs),
    /// Check a TypeScript script and optionally validate target expressions.
    ScriptCheck(script_client::CheckArgs),
    /// Check and run a TypeScript script on an offline core.
    ScriptRun(script_client::RunArgs),
    /// Launch a process on the server and handle signals from its first instruction.
    Run(RunTargetArgs),
    /// Get a detached run's current state or final result.
    RunStatus(aidbg::run::RunId),
    /// List retained runs and their states.
    RunList,
    /// Pause a detached run and stop its threads.
    RunPause(aidbg::run::RunId),
    /// Resume a paused run.
    RunContinue(aidbg::run::RunId),
    /// Request cancellation of a detached run.
    RunCancel(aidbg::run::RunId),
    /// Execute one machine instruction in a paused run.
    Step(StepArgs),
    /// Step over a call in a paused run.
    Next(StepArgs),
    /// Step until the selected frame returns.
    StepOut(StepArgs),
    /// Open a core retained by the server.
    CoreOpen(script_client::OpenArgs),
    /// Close a core retained by the server.
    CoreClose(script_client::CloseArgs),

    /// Track value changes within a bounded single-step window.
    WatchStep(WatchStepArgs),
    /// Read a byte range from a live process or open core.
    ReadMemory(ReadMemoryArgs),
    /// Invoke a native scalar function using an explicit scratch stack and step budget.
    TargetCall(TargetCallArgs),
    /// Capture a live snapshot or look up a saved snapshot.
    Snapshot(SnapshotArgs),
    /// Save a compressed Linux ELF core from a live process.
    Coredump(CoredumpArgs),
    /// Extend retention for an existing server core.
    CoreRetain(coredump_client::RetainArgs),
    /// Export a retained core and its verified images as a replayable directory.
    ExportBundle(coredump_client::BundleArgs),
    /// Restore a bundle's breakpoints in a paused run.
    RestoreBreakpoints(coredump_client::RestoreArgs),
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

#[derive(Args)]
struct RunTargetArgs {
    /// TypeScript file registering signal callbacks.
    #[arg(long = "on-signal", value_name = "FILE")]
    signal_file: Option<PathBuf>,
    /// Absolute working directory on the server.
    #[arg(long)]
    cwd: Option<PathBuf>,
    /// Run timeout in milliseconds (default 30000).
    #[arg(long)]
    timeout_ms: Option<u32>,
    #[arg(long)]
    detach: bool,
    /// Return with the process stopped at the initial exec event.
    #[arg(long)]
    pause_at_entry: bool,
    /// Save a retained core when the target reaches its exit stop.
    #[arg(long)]
    exit_coredump: bool,
    /// Override a server environment variable (repeatable).
    #[arg(long, value_name = "NAME=VALUE")]
    env: Vec<String>,
    /// Pass text to stdin, followed by EOF.
    #[arg(long)]
    stdin: Option<String>,
    /// Absolute executable path on the server.
    executable: PathBuf,
    /// Arguments for the target process, passed without shell expansion.
    #[arg(last = true)]
    arguments: Vec<String>,
}

impl RunTargetArgs {
    fn message(self) -> AidbgResult<aidbg::run::RunRequest> {
        Ok(aidbg::run::RunRequest {
            executable: self.executable,
            arguments: self.arguments,
            env: self
                .env
                .into_iter()
                .map(|entry| {
                    entry
                        .split_once('=')
                        .map(|(name, value)| (name.to_owned(), value.to_owned()))
                        .ok_or_else(|| io::Error::other("expected --env NAME=VALUE"))
                })
                .collect::<Result<_, _>>()?,
            stdin: self.stdin,
            pause_at_entry: self.pause_at_entry,
            exit_coredump: self.exit_coredump,
            cwd: self.cwd,
            signal_source: self
                .signal_file
                .as_deref()
                .map(script_client::read_source)
                .transpose()?,
            timeout_ms: self.timeout_ms,
            detach: self.detach,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct ReadMemoryArgs {
    #[arg(long, group = "memory_target")]
    target_id: Option<String>,
    #[arg(long, group = "memory_target")]
    pid: Option<i32>,
    #[arg(long, group = "memory_target")]
    run_id: Option<String>,
    #[arg(long)]
    address: String,
    #[arg(long)]
    length: u32,
}

#[derive(Args, Deserialize, JsonSchema)]
struct StepArgs {
    #[arg(long)]
    run_id: String,
    #[arg(long)]
    tid: Option<i32>,
    #[arg(long)]
    max_steps: Option<u32>,
    #[arg(long)]
    timeout_ms: Option<u32>,
}

impl StepArgs {
    fn message(self, mode: rpc::step_run_request::Mode) -> rpc::StepRunRequest {
        rpc::StepRunRequest {
            run_id: self.run_id,
            tid: self.tid,
            max_steps: self.max_steps,
            timeout_ms: self.timeout_ms,
            mode: mode as i32,
        }
    }
}

impl ReadMemoryArgs {
    fn message(self) -> AidbgResult<rpc::ReadMemoryRequest> {
        let count = usize::from(self.target_id.is_some())
            + usize::from(self.pid.is_some())
            + usize::from(self.run_id.is_some());
        if count != 1 {
            return Err(aidbg::Diagnostic::new(
                if count > 1 {
                    "CONFLICTING_TARGET"
                } else {
                    "INVALID_ARGUMENT"
                },
                "Specify one of target_id, pid or run_id",
                None,
            )
            .into());
        }
        Ok(rpc::ReadMemoryRequest {
            target_id: self.target_id,
            pid: self.pid,
            run_id: self.run_id,
            address: parse_address(&self.address)?,
            length: self.length,
        })
    }
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
    Update(BreakpointUpdateArgs),
    Remove(RemoveArgs),
    Events(EventsArgs),
    Capabilities(CapabilityArgs),
    List(CapabilityArgs),
}

#[derive(Args, Deserialize, JsonSchema)]
struct BreakpointUpdateArgs {
    #[arg(long)]
    breakpoint_id: u64,
    #[arg(long)]
    address: Option<String>,
    #[arg(long)]
    rule_id: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
struct BreakpointWorkflowArgs {
    run_id: Option<String>,
    run: Option<aidbg::run::RunRequest>,
    points: Vec<WorkflowPoint>,
    /// Total script budget in milliseconds. Defaults to 1000.
    #[schemars(range(min = 1, max = 10000))]
    timeout_ms: Option<u32>,
    /// Default per-hit callback budget in milliseconds. Defaults to 100.
    #[schemars(range(min = 1, max = 500))]
    per_hit_timeout_ms: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct WorkflowPoint {
    address: Option<String>,
    symbol: Option<String>,
    module: Option<String>,
    offset: Option<String>,
    #[serde(default)]
    kind: RuleKind,
    length: Option<u32>,
    tid: Option<i32>,
    #[serde(default)]
    expressions: Vec<String>,
    /// Override the per-hit callback budget for this point.
    #[schemars(range(min = 1, max = 500))]
    timeout_ms: Option<u32>,
}

impl BreakpointWorkflowArgs {
    fn source(&self, addresses: &[u64]) -> AidbgResult<String> {
        if !(1..=32).contains(&self.points.len()) {
            return Err(aidbg::Diagnostic::new(
                "INVALID_ARGUMENT",
                "provide 1–32 workflow points",
                None,
            )
            .into());
        }
        let mut source = String::from("export default async function main() {\n");
        for (point, address) in self.points.iter().zip(addresses) {
            if point.expressions.len() > 16
                || point.expressions.iter().any(|expr| expr.len() > 512)
                || point.tid.is_some_and(|tid| tid <= 0)
            {
                return Err(aidbg::Diagnostic::new(
                    "INVALID_ARGUMENT",
                    "invalid workflow expressions or TID",
                    None,
                )
                .into());
            }
            let callback = format!(
                "(hit: BreakpointHit) => {{ for (const expr of {}) hit.printVal(expr); }}",
                serde_json::to_string(&point.expressions)?
            );
            let timeout = point.timeout_ms.or(self.per_hit_timeout_ms).unwrap_or(100);
            let mut options = serde_json::json!({"timeoutMs": timeout});
            if let Some(tid) = point.tid {
                options["tid"] = tid.into();
            }
            let invocation = match (point.kind, point.length) {
                (RuleKind::Hardware, None) => {
                    format!("dbg.hardwareBreakpoint({address}n,{callback},{options});")
                }
                (RuleKind::Software, None) => {
                    format!("dbg.softwareBreakpoint({address}n,{callback},{options});")
                }
                (
                    mode @ (RuleKind::Read | RuleKind::Write | RuleKind::ReadWrite),
                    Some(length @ (1 | 2 | 4 | 8)),
                ) => {
                    let access = match mode {
                        RuleKind::Read => "read",
                        RuleKind::Write => "write",
                        _ => "read_write",
                    };
                    format!(
                        "dbg.watchpoint({address}n,{length},\"{access}\",{callback},{options});"
                    )
                }
                _ => {
                    return Err(aidbg::Diagnostic::new(
                        "INVALID_ARGUMENT",
                        "workflow watchpoints require length 1, 2, 4 or 8",
                        None,
                    )
                    .into());
                }
            };
            source.push_str(&invocation);
            source.push('\n');
        }
        source.push_str("dbg.continue();\nreturn await dbg.events();\n}");
        Ok(source)
    }
}

impl BreakpointUpdateArgs {
    fn message(self) -> AidbgResult<rpc::UpdateBreakpointRequest> {
        Ok(rpc::UpdateBreakpointRequest {
            breakpoint_id: self.breakpoint_id,
            address: self.address.as_deref().map(parse_address).transpose()?,
            rule_id: self.rule_id,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct CapabilityArgs {
    #[arg(long, conflicts_with = "run_id")]
    pid: Option<i32>,
    #[arg(long)]
    run_id: Option<String>,
}

#[derive(Clone, Copy, Default, Deserialize, JsonSchema, ValueEnum)]
#[serde(rename_all = "snake_case")]
enum RuleKind {
    #[default]
    Hardware,
    Software,
    Read,
    Write,
    ReadWrite,
}

#[derive(Args, Deserialize, JsonSchema)]
struct BreakpointArgs {
    #[arg(long, required_unless_present = "run_id", conflicts_with = "run_id")]
    pid: Option<i32>,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long, value_enum, default_value = "hardware")]
    #[serde(default)]
    kind: RuleKind,
    /// Watch width in bytes (required for hardware watchpoints).
    #[arg(long)]
    length: Option<u32>,
    /// Absolute runtime address in decimal or 0x-prefixed hex.
    #[arg(long, conflicts_with_all = ["module", "symbol", "instance", "file", "line", "offset"])]
    address: Option<String>,
    /// Exact path, basename or build ID of the loaded module.
    #[arg(long)]
    module: Option<String>,
    /// Exact ELF symbol name. module is optional.
    #[arg(long, conflicts_with = "file")]
    symbol: Option<String>,
    /// Offset from the selected ELF symbol or module base.
    #[arg(long, conflicts_with = "file")]
    offset: Option<String>,
    /// Source file path or suffix, as recorded in DWARF.
    #[arg(long, requires = "line")]
    file: Option<PathBuf>,
    /// One-based source line.
    #[arg(long, requires = "file")]
    line: Option<u64>,
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
    /// TypeScript callback file. Use script-api --mode breakpoint for its API.
    #[arg(long = "rule", value_name = "FILE")]
    #[serde(skip)]
    #[schemars(skip)]
    rule_file: Option<PathBuf>,
    /// Inline TypeScript callback source. Export a default function accepting BreakpointHit,
    /// or use defineRule. Use script_api with mode breakpoint for declarations.
    #[arg(skip)]
    rule_source: Option<String>,
    /// Named rule ID from rule_define. Mutually exclusive with rule_source.
    #[arg(long, conflicts_with = "rule_file")]
    rule_id: Option<u64>,
    /// Limit a breakpoint or watchpoint to this Linux thread.
    #[arg(long)]
    tid: Option<i32>,
    /// Registered callback export, for example $.onHit.
    #[arg(long, conflicts_with_all = ["rule_id", "rule_file"])]
    handler: Option<String>,
    /// Keep the run stopped after a hit until run_continue. Requires run_id.
    #[arg(long, requires = "run_id")]
    #[serde(default)]
    stop_after_hit: bool,
}

impl BreakpointArgs {
    fn message(self) -> AidbgResult<InstallBreakpointRequest> {
        use install_breakpoint_request::Location;
        let location = match (
            self.address,
            self.module,
            self.symbol,
            self.instance,
            self.file,
            self.line,
            self.offset,
        ) {
            (Some(address), None, None, None, None, None, None) => {
                Location::Address(parse_address(&address)?)
            }
            (None, module, Some(symbol), instance, None, None, offset) => {
                Location::Symbol(SymbolLocation {
                    module: module.unwrap_or_default(),
                    symbol,
                    instance: instance.as_deref().map(parse_address).transpose()?,
                    offset: offset.as_deref().map(parse_address).transpose()?,
                })
            }
            (None, Some(module), None, instance, None, None, Some(offset)) => {
                Location::ModuleOffset(rpc::ModuleOffsetLocation {
                    module,
                    offset: parse_address(&offset)?,
                    instance: instance.as_deref().map(parse_address).transpose()?,
                })
            }
            (None, module, None, instance, Some(file), Some(line), None)
                if line > 0 && !file.as_os_str().is_empty() =>
            {
                Location::Source(rpc::SourceLocation {
                    file: file
                        .into_os_string()
                        .into_string()
                        .map_err(|_| io::Error::other("source file must be valid UTF-8"))?,
                    line,
                    module,
                    instance: instance.as_deref().map(parse_address).transpose()?,
                })
            }
            _ => {
                return Err(aidbg::Diagnostic::new("INVALID_ARGUMENT",
                    "provide address, symbol with optional module, module with offset, or file and line", None,
                )
                .into());
            }
        };
        let rule_source = match self.rule_file {
            Some(path) => Some(script_client::read_source(&path)?),
            None => self.rule_source,
        };
        Ok(InstallBreakpointRequest {
            pid: self.pid.unwrap_or_default(),
            run_id: self.run_id,
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
                RuleKind::Read => BreakpointKind::Read,
                RuleKind::Write => BreakpointKind::Write,
                RuleKind::ReadWrite => BreakpointKind::ReadWrite,
            } as i32,
            length: self.length,
            rule_source,
            rule_id: self.rule_id,
            tid: self.tid,
            handler: self.handler,
            replay_export: None,
            stop_after_hit: self.stop_after_hit,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct RemoveArgs {
    #[arg(long, required_unless_present = "run_id", conflicts_with = "run_id")]
    pid: Option<i32>,
    #[arg(long)]
    run_id: Option<String>,
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
    #[arg(
        long,
        required_unless_present_any = ["target_id", "run_id"],
        conflicts_with_all = ["target_id", "run_id"]
    )]
    pid: Option<i32>,
    #[arg(long, conflicts_with = "run_id")]
    target_id: Option<String>,
    #[arg(long)]
    run_id: Option<String>,
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
    fn message(self) -> AidbgResult<SearchSymbolsRequest> {
        validate_run_selector(self.pid, self.target_id.as_deref(), self.run_id.as_deref())?;
        Ok(SearchSymbolsRequest {
            pid: self.pid.unwrap_or_default(),
            target_id: self.target_id,
            run_id: self.run_id,
            pattern: self.pattern,
            match_mode: match self.mode {
                MatchMode::Exact => SymbolMatch::Exact,
                MatchMode::Glob => SymbolMatch::Glob,
                MatchMode::Regex => SymbolMatch::Regex,
            } as i32,
            module: self.module,
            limit: self.limit,
        })
    }
}

fn validate_run_selector(
    pid: Option<i32>,
    target_id: Option<&str>,
    run_id: Option<&str>,
) -> AidbgResult<()> {
    match (pid, target_id, run_id) {
        (None, None, Some(id)) if !id.is_empty() => Ok(()),
        (_, _, None) => validate_target(pid, target_id),
        _ => Err(aidbg::Diagnostic::new(
            "INVALID_ARGUMENT",
            "Specify exactly one of pid, target_id or run_id",
            None,
        )
        .into()),
    }
}

fn validate_target(pid: Option<i32>, target_id: Option<&str>) -> AidbgResult<()> {
    match (pid, target_id) {
        (Some(pid), None) if pid > 0 => Ok(()),
        (None, Some(id)) if !id.is_empty() => Ok(()),
        _ => Err(aidbg::Diagnostic::new(
            "INVALID_ARGUMENT",
            "Specify exactly one positive pid or a target_id",
            None,
        )
        .into()),
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct ResolveArgs {
    #[arg(
        long,
        required_unless_present = "target_id",
        conflicts_with = "target_id"
    )]
    pid: Option<i32>,
    #[arg(long)]
    target_id: Option<String>,
    #[arg(long)]
    address: String,
}

impl ResolveArgs {
    fn message(self) -> AidbgResult<ResolveAddressRequest> {
        validate_target(self.pid, self.target_id.as_deref())?;
        Ok(ResolveAddressRequest {
            pid: self.pid.unwrap_or_default(),
            target_id: self.target_id,
            address: parse_address(&self.address)?,
        })
    }
}

#[derive(Args, Deserialize, JsonSchema)]
struct DisassembleArgs {
    #[arg(
        long,
        required_unless_present_any = ["target_id", "run_id"],
        conflicts_with_all = ["target_id", "run_id"]
    )]
    pid: Option<i32>,
    #[arg(long, conflicts_with = "run_id")]
    target_id: Option<String>,
    #[arg(long)]
    run_id: Option<String>,
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
        validate_run_selector(self.pid, self.target_id.as_deref(), self.run_id.as_deref())?;
        Ok(DisassembleRequest {
            pid: self.pid.unwrap_or_default(),
            target_id: self.target_id,
            run_id: self.run_id,
            address: parse_address(&self.address)?,
            before: self.before,
            after: self.after,
            start: self.start.as_deref().map(parse_address).transpose()?,
        })
    }
}

#[derive(Deserialize, JsonSchema)]
struct CapturedMemory {
    address: String,
    length: u32,
    bytes: String,
}

#[derive(Deserialize, JsonSchema)]
struct MemoryDiffTool {
    before: CapturedMemory,
    after: CapturedMemory,
    /// Return at most this many changed bytes, default 128, maximum 1024.
    limit: Option<usize>,
    /// Begin reporting changes from this byte offset.
    offset: Option<usize>,
}

impl MemoryDiffTool {
    fn compare(self) -> AidbgResult<Value> {
        use serde_json::json;

        let invalid = |message| aidbg::Diagnostic::new("INVALID_ARGUMENT", message, None);
        let address = parse_address(&self.before.address)?;
        let length = self.before.length as usize;
        let offset = self.offset.unwrap_or_default();
        let limit = self.limit.unwrap_or(128);
        if !(1..=65_536).contains(&length)
            || length != self.after.length as usize
            || address != parse_address(&self.after.address)?
            || address.checked_add(length as u64).is_none()
            || offset > length
            || !(1..=1024).contains(&limit)
        {
            return Err(invalid("Snapshots must describe the same range, with an in-range offset and limit from 1 to 1024").into());
        }
        if self.before.bytes.len() > length * 2 || self.after.bytes.len() > length * 2 {
            return Err(invalid("Snapshot bytes exceed the declared range").into());
        }
        let before = hex_bytes(&self.before.bytes)?;
        let after = hex_bytes(&self.after.bytes)?;
        let compared = before.len().min(after.len());
        let mut differences = before
            .iter()
            .zip(&after)
            .enumerate()
            .skip(offset)
            .filter(|(_, (old, new))| old != new);
        let changes: Vec<_> = differences.by_ref().take(limit).map(|(offset, (old, new))| {
            json!({"offset": offset, "before": format!("{old:02x}"), "after": format!("{new:02x}")})
        }).collect();
        let next_offset = differences.next().map(|(offset, _)| offset);
        Ok(json!({
            "address": aidbg::hex(address), "length": length,
            "before_bytes_read": before.len(), "after_bytes_read": after.len(),
            "compared_bytes": compared, "complete": compared == length,
            "first_uncompared_address": (compared < length).then(|| aidbg::hex(address + compared as u64)),
            "changes": changes, "next_offset": next_offset,
        }))
    }
}

#[derive(Deserialize, JsonSchema)]
struct MemorySearchTool {
    target_id: Option<String>,
    pid: Option<i32>,
    run_id: Option<String>,
    /// Hexadecimal bytes without separators.
    pattern: String,
    start: Option<String>,
    end: Option<String>,
    limit: Option<u32>,
    max_scan_bytes: Option<u32>,
    alignment: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct XrefTool {
    target_id: Option<String>,
    pid: Option<i32>,
    run_id: Option<String>,
    address: String,
    /// Use a bounded executable interval with a known instruction boundary at start.
    #[serde(default)]
    instruction_references: bool,
    start: Option<String>,
    end: Option<String>,
    limit: Option<u32>,
    max_scan_bytes: Option<u32>,
    /// Continue instruction results from next_address, keeping the original start and end.
    resume_from: Option<String>,
    /// Byte alignment of pointer candidates. Defaults to 8.
    alignment: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
struct PointerChainTool {
    target_id: Option<String>,
    pid: Option<i32>,
    run_id: Option<String>,
    base: String,
    offsets: Vec<i64>,
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
    #[arg(long, required_unless_present_any = ["run_id", "target_id"], conflicts_with_all = ["run_id", "target_id"])]
    pid: Option<i32>,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    tid: Option<i32>,
    #[arg(
        long,
        required_unless_present = "expressions",
        conflicts_with = "expressions"
    )]
    expression: Option<String>,
    #[arg(long, value_name = "EXPRESSION")]
    #[serde(default)]
    expressions: Vec<String>,
    #[arg(long, conflicts_with = "run_id")]
    target_id: Option<String>,
    #[arg(long)]
    frame_index: Option<u32>,
    #[arg(long)]
    module: Option<String>,
    #[arg(long)]
    instance: Option<String>,
    #[arg(long)]
    timeout_ms: Option<u32>,
    #[arg(skip)]
    expand: Option<InspectPageArgs>,
    #[arg(long)]
    #[serde(skip)]
    expand_offset: Option<u32>,
    #[arg(long)]
    #[serde(skip)]
    expand_limit: Option<u32>,
}

impl InspectArgs {
    fn message(self) -> AidbgResult<InspectRequest> {
        Ok(InspectRequest {
            pid: self.pid.unwrap_or_default(),
            run_id: self.run_id,
            tid: self.tid,
            expression: self.expression.unwrap_or_default(),
            expressions: self.expressions,
            target_id: self.target_id,
            frame_index: self.frame_index,
            timeout_ms: self.timeout_ms,
            expand: self
                .expand
                .or_else(|| {
                    (self.expand_offset.is_some() || self.expand_limit.is_some()).then_some(
                        InspectPageArgs {
                            offset: self.expand_offset.unwrap_or_default(),
                            limit: self.expand_limit,
                        },
                    )
                })
                .map(|page| rpc::InspectExpansion {
                    offset: page.offset,
                    limit: page.limit,
                }),
            module: self.module,
            instance: self.instance.as_deref().map(parse_address).transpose()?,
        })
    }
}

#[derive(Deserialize, JsonSchema)]
struct InspectPageArgs {
    #[serde(default)]
    offset: u32,
    limit: Option<u32>,
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
    #[arg(
        long,
        required_unless_present = "target_id",
        conflicts_with = "target_id"
    )]
    original: Option<String>,
    #[arg(long)]
    target_id: Option<String>,
    /// Number of original bytes to read from a core at base.
    #[arg(long, requires = "target_id")]
    original_length: Option<u32>,
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
            original: self
                .original
                .as_deref()
                .map(hex_bytes)
                .transpose()?
                .unwrap_or_default(),
            target_id: self.target_id,
            original_length: self.original_length,
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
    code: Option<String>,
    target_id: Option<String>,
    frame: Option<String>,
    code_length: Option<u32>,
    #[serde(default)]
    core_memory: Vec<CoreMemoryArgs>,
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
struct CoreMemoryArgs {
    address: String,
    length: u32,
    #[serde(default)]
    writable: bool,
    #[serde(default)]
    overlays: Vec<MemoryArgs>,
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
        let core_memory = self
            .core_memory
            .into_iter()
            .map(|range| {
                let overlays = range
                    .overlays
                    .into_iter()
                    .map(|copy| {
                        Ok(MemoryCopy {
                            address: parse_address(&copy.address)?,
                            contents: hex_bytes(&copy.bytes)?,
                            writable: false,
                        })
                    })
                    .collect::<AidbgResult<_>>()?;
                Ok(rpc::CoreMemoryCopy {
                    address: parse_address(&range.address)?,
                    length: range.length,
                    writable: range.writable,
                    overlays,
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
            code: self
                .code
                .as_deref()
                .map(hex_bytes)
                .transpose()?
                .unwrap_or_default(),
            target_id: self.target_id,
            frame: self.frame,
            code_length: self.code_length,
            core_memory,
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
    #[arg(long, required_unless_present_any = ["from", "event", "run_id"], conflicts_with_all = ["from", "event", "run_id"])]
    pid: Option<i32>,
    /// Capture through the owner of a detached run's tracer.
    #[arg(long, conflicts_with_all = ["from", "event"])]
    run_id: Option<String>,
    /// Query this saved snapshot ID instead of capturing a PID.
    #[arg(long)]
    from: Option<String>,
    /// Query the snapshot saved for this breakpoint event ID.
    #[arg(long, conflicts_with = "from")]
    event: Option<u64>,
    #[arg(long, conflicts_with_all = ["from", "event"], value_enum)]
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

fn run_request(id: &aidbg::run::RunId) -> Request<rpc::ScriptDocumentRequest> {
    request(rpc::ScriptDocumentRequest {
        json: serde_json::to_vec(id).expect("run ID serializes"),
    })
}

fn rule_request(args: &impl serde::Serialize) -> AidbgResult<rpc::ScriptDocumentRequest> {
    Ok(rpc::ScriptDocumentRequest {
        json: serde_json::to_vec(args)?,
    })
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
        client
            .snapshot(request(SnapshotRequest {
                pid: args.pid.unwrap_or_default(),
                run_id: args.run_id,
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
    pid: Option<i32>,
    /// Capture through a detached run's tracer.
    run_id: Option<String>,
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

#[derive(Deserialize, JsonSchema)]
struct ConnectTool {
    /// HTTP endpoint of the Linux server or SSH forward. Defaults to http://127.0.0.1:55051.
    endpoint: Option<String>,
    /// Absolute Unix socket path for a server reachable from Linux.
    socket: Option<PathBuf>,
}

struct Mcp {
    scripts: script_client::Client,
}

fn tool_reply(
    result: std::result::Result<tonic::Response<SnapshotReply>, tonic::Status>,
) -> CallToolResult {
    tool_document(result.map(|reply| reply.into_inner().snapshot_json))
}

fn tool_document(result: std::result::Result<Vec<u8>, tonic::Status>) -> CallToolResult {
    match result {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(doc) => structured_document(doc),
            Err(error) => result_error(error.into()),
        },
        Err(e) => result_error(e.into()),
    }
}

fn document_tool(
    result: std::result::Result<tonic::Response<DocumentReply>, tonic::Status>,
) -> CallToolResult {
    tool_document(result.map(|reply| reply.into_inner().json))
}

fn argument_error(error: impl ToString) -> CallToolResult {
    result_error(aidbg::Diagnostic::new("INVALID_ARGUMENT", error.to_string(), None).into())
}

fn structured_document(mut document: Value) -> CallToolResult {
    let failed = matches!(
        document["status"].as_str(),
        Some("failed" | "timed_out" | "cleanup_failed")
    );
    if let Some(object) = document.as_object_mut() {
        object
            .entry("warnings")
            .or_insert_with(|| serde_json::json!([]));
    }
    if failed {
        let first_error = document["diagnostics"]
            .as_array()
            .and_then(|diagnostics| {
                diagnostics
                    .iter()
                    .find(|diagnostic| diagnostic["severity"] == "error")
            })
            .cloned()
            .unwrap_or_default();
        if document["code"].is_null() {
            document["code"] = first_error["code"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| document["status"].as_str().map(str::to_ascii_uppercase))
                .into();
        }
        if document["message"].is_null() {
            document["message"] = first_error["message"]
                .as_str()
                .or_else(|| document["issue"].as_str())
                .unwrap_or("Debugger operation did not complete")
                .into();
        }
        if document.get("hint").is_none() {
            document["hint"] = Value::Null;
        }
        CallToolResult::structured_error(document)
    } else {
        CallToolResult::structured(document)
    }
}

fn result_error(error: Box<dyn std::error::Error + Send + Sync>) -> CallToolResult {
    let default =
        |code, message| serde_json::json!({"code": code, "message": message, "hint": null});
    let detail = if let Some(diagnostic) = error.downcast_ref::<aidbg::Diagnostic>() {
        serde_json::json!(diagnostic)
    } else if let Some(status) = error.downcast_ref::<tonic::Status>() {
        serde_json::from_slice::<Value>(status.details())
            .ok()
            .filter(|detail| detail["code"].is_string() && detail["message"].is_string())
            .unwrap_or_else(|| {
                default(
                    match status.code() {
                        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
                        tonic::Code::NotFound => "NOT_FOUND",
                        tonic::Code::PermissionDenied => "PERMISSION_DENIED",
                        tonic::Code::Unimplemented => "UNSUPPORTED",
                        tonic::Code::Unavailable => "SERVER_UNAVAILABLE",
                        tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
                        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
                        tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
                        _ => "INTERNAL_ERROR",
                    },
                    status.message().to_owned(),
                )
            })
    } else {
        default("FAILED_PRECONDITION", error.to_string())
    };
    CallToolResult::structured_error(serde_json::json!({
        "error": detail["message"], "code": detail["code"],
        "message": detail["message"], "hint": detail["hint"], "warnings": []
    }))
}

fn script_tool(result: AidbgResult<Value>) -> CallToolResult {
    match result {
        Ok(result) => structured_document(result),
        Err(error) => result_error(error),
    }
}

macro_rules! mcp_client {
    ($server:ident) => {
        match $server.scripts.remote() {
            Ok(client) => client,
            Err(error) => return result_error(error),
        }
    };
}

#[rmcp::tool_handler(router = Self::tool_router())]
impl rmcp::ServerHandler for Mcp {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("aidbg", aidbg::BUILD_VERSION))
            .with_instructions(
                "Call capabilities to find debugger tools by task and target selector.",
            )
    }
}

#[tool_router]
impl Mcp {
    #[tool(
        description = "Find debugger tools by task and target. Shows selectors, common entry points, and how to attach to an existing PID."
    )]
    async fn capabilities(&self) -> CallToolResult {
        CallToolResult::structured(serde_json::json!({
            "targets": {
                "run_id": "Run started by run with detach or pause_at_entry",
                "pid": "Existing Linux process. Tools using pid can inspect or attach directly.",
                "target_id": "Offline core opened by core_open"
            },
            "tools": {
                "runs": {"start": "run", "active": "run_list", "control": ["run_status", "run_pause", "run_continue", "run_cancel"], "step": ["step", "next", "step_out"], "selector": "run_id"},
                "variables": {
                    "tool": "inspect", "selectors": ["run_id", "pid", "target_id"],
                    "example": {"target_id": "core-id", "tid": 123, "frame_index": 0, "expressions": ["account->id", "account->profile"]},
                    "address": "result.address, or results[].value.result.address for a core batch"
                },
                "memory": {"tools": ["read_memory", "search_memory", "xref", "pointer_chain"], "selectors": ["run_id", "pid", "target_id"], "compare_captures": "memory_diff"},
                "breakpoints": {"tools": ["breakpoint_set", "breakpoint_list", "breakpoint_remove"], "selectors": ["run_id", "pid"], "events": "breakpoint_events"},
                "core": {"open": "core_open", "open_by": ["path", "dump_id"], "close": "core_close"},
                "threads": {"tool": "observe_threads", "selectors": ["run_id", "pid", "target_id"], "stack_snapshot": "snapshot", "saved_snapshot": "snapshot_query"},
                "types": {"tool": "script_run", "selectors": ["run_id", "target_id"], "example": r#"return dbg.types("Queue");"#}
            }
        }))
    }

    #[tool(
        description = "Connect this MCP session to an aidbg server. Call with {} for http://127.0.0.1:55051, or specify a direct endpoint or Unix socket."
    )]
    async fn connect(&self, Parameters(args): Parameters<ConnectTool>) -> CallToolResult {
        let result = async {
            if args.socket.is_some() && args.endpoint.is_some() {
                return Err(io::Error::other("specify either endpoint or socket").into());
            }
            let tcp = args
                .endpoint
                .as_deref()
                .or_else(|| args.socket.is_none().then_some("http://127.0.0.1:55051"));
            let endpoint = rpc::endpoint(args.socket.as_deref(), tcp)?
                .ok_or_else(|| io::Error::other("missing server address"))?;
            let mut client = rpc::connect(endpoint).await?;
            let mut probe = Request::new(rpc::ServerInfoRequest {});
            probe.set_timeout(Duration::from_secs(3));
            let server = match client.server_info(probe).await {
                Ok(reply) => Some(serde_json::from_slice::<Value>(&reply.into_inner().json)?),
                Err(status) if status.code() == tonic::Code::Unimplemented => {
                    let mut legacy = Request::new(rpc::ScriptDocumentRequest { json: b"{}".to_vec() });
                    legacy.set_timeout(Duration::from_secs(3));
                    client.script_api(legacy).await?;
                    None
                }
                Err(status) => return Err(status.into()),
            };
            self.scripts.set_remote(client)?;
            Ok(serde_json::json!({
                "status": "connected",
                "endpoint": tcp,
                "socket": args.socket,
                "client": { "version": aidbg::VERSION, "revision": aidbg::BUILD_REVISION },
                "server": server,
                "warnings": if server.is_none() {
                    vec![serde_json::json!({"code": "SERVER_VERSION_UNAVAILABLE", "message": "The connected server does not report its build identity."})]
                } else {
                    Vec::new()
                },
            }))
        }
        .await;
        script_tool(result)
    }

    #[tool(
        description = "Launch a server-side executable under the tracer. Optionally register TypeScript signal handlers before launch. Returns output and retained coredump IDs, or a run_id and PID with detach or pause_at_entry enabled."
    )]
    async fn run(&self, Parameters(args): Parameters<aidbg::run::RunRequest>) -> CallToolResult {
        match serde_json::to_vec(&args) {
            Ok(json) => document_tool(
                mcp_client!(self)
                    .run_target(Request::new(rpc::ScriptDocumentRequest { json }))
                    .await,
            ),
            Err(error) => argument_error(error),
        }
    }

    #[tool(description = "Get the current state or final output of a detached run.")]
    async fn run_status(&self, Parameters(args): Parameters<aidbg::run::RunId>) -> CallToolResult {
        document_tool(mcp_client!(self).run_status(run_request(&args)).await)
    }

    #[tool(description = "List retained runs, PIDs and states.")]
    async fn run_list(&self) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .run_list(request(rpc::ScriptDocumentRequest { json: vec![] }))
                .await,
        )
    }

    #[tool(
        description = "Stop all threads in a detached run. The run timeout continues while paused."
    )]
    async fn run_pause(&self, Parameters(args): Parameters<aidbg::run::RunId>) -> CallToolResult {
        document_tool(mcp_client!(self).run_pause(run_request(&args)).await)
    }

    #[tool(description = "Resume a detached run stopped by pause_at_entry or run_pause.")]
    async fn run_continue(
        &self,
        Parameters(args): Parameters<aidbg::run::RunId>,
    ) -> CallToolResult {
        document_tool(mcp_client!(self).run_continue(run_request(&args)).await)
    }

    #[tool(description = "Request cancellation of a detached run.")]
    async fn run_cancel(&self, Parameters(args): Parameters<aidbg::run::RunId>) -> CallToolResult {
        document_tool(mcp_client!(self).run_cancel(run_request(&args)).await)
    }

    #[tool(
        description = "Step one machine instruction in a paused run. Other threads remain stopped."
    )]
    async fn step(&self, Parameters(args): Parameters<StepArgs>) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .step_run(request(args.message(rpc::step_run_request::Mode::Step)))
                .await,
        )
    }

    #[tool(
        description = "Step one instruction, or step over a call to its return address, in a paused run."
    )]
    async fn next(&self, Parameters(args): Parameters<StepArgs>) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .step_run(request(args.message(rpc::step_run_request::Mode::Next)))
                .await,
        )
    }

    #[tool(description = "Step until the selected frame returns or the step budget is exhausted.")]
    async fn step_out(&self, Parameters(args): Parameters<StepArgs>) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .step_run(request(args.message(rpc::step_run_request::Mode::Out)))
                .await,
        )
    }

    #[tool(
        description = "Get TypeScript declarations and an example. Use mode \"live\" to install breakpoints from a script, or mode \"breakpoint\" for BreakpointHit, including watch values, inspect, memory with native DataView, snapshots, and disable(). The example shows a default-export callback with state across hits."
    )]
    async fn script_api(
        &self,
        Parameters(args): Parameters<aidbg::script::ApiRequest>,
    ) -> CallToolResult {
        script_tool(self.scripts.api(args).await)
    }

    #[tool(
        description = "Type-check offline scripts, live installation scripts, breakpoint callbacks, or signal handlers. Set mode to \"breakpoint\" for an onHit callback. Offline checks can validate literal expressions against a core."
    )]
    async fn script_check(
        &self,
        Parameters(args): Parameters<aidbg::script::CheckRequest>,
    ) -> CallToolResult {
        script_tool(self.scripts.check(args).await)
    }

    #[tool(
        description = "Run checked TypeScript on an open core by target_id, or install breakpoints synchronously in a live tracer by run_id. Use script_api with mode live for the live API."
    )]
    async fn script_run(
        &self,
        Parameters(args): Parameters<aidbg::script::RunRequest>,
    ) -> CallToolResult {
        script_tool(self.scripts.run(args).await)
    }

    #[tool(
        description = "Open a local ELF core or core.zst by path, or a retained server core by dump_id. Windows uploads local files automatically. Use upload=true on Linux for server analysis. Up to 16 cores can be open per store. The server may configure a lower limit."
    )]
    async fn core_open(
        &self,
        Parameters(args): Parameters<aidbg::script::OpenRequest>,
    ) -> CallToolResult {
        script_tool(self.scripts.open(args).await)
    }

    #[tool(description = "Close an open core target.")]
    async fn core_close(
        &self,
        Parameters(args): Parameters<aidbg::script::CloseRequest>,
    ) -> CallToolResult {
        script_tool(self.scripts.close(args).await)
    }

    #[tool(
        description = "Save a compressed Linux ELF core from pid or run_id to a client-side path. Paused runs remain stopped. Set resume to true with the original output path to resume a download. Returns the dump ID, coverage, and output metadata."
    )]
    async fn coredump(&self, Parameters(args): Parameters<CoredumpArgs>) -> CallToolResult {
        match save_coredump(mcp_client!(self), args).await {
            Ok(summary) => CallToolResult::structured(summary),
            Err(error) => argument_error(error),
        }
    }

    #[tool(description = "Extend a server core's retention from now, up to 30 days.")]
    async fn core_retain(
        &self,
        Parameters(args): Parameters<coredump_client::RetainArgs>,
    ) -> CallToolResult {
        script_tool(coredump_client::retain_core(mcp_client!(self), args).await)
    }

    #[tool(
        description = "Export a retained core, verified executable, optional script, output and notes into a new client-side directory."
    )]
    async fn export_bundle(
        &self,
        Parameters(args): Parameters<coredump_client::BundleArgs>,
    ) -> CallToolResult {
        script_tool(coredump_client::export_bundle(mcp_client!(self), args).await)
    }

    #[tool(
        description = "Restore exported breakpoints from a local bundle into a paused run. Use launch=true to upload and start the bundled executable on the server."
    )]
    async fn restore_breakpoints(
        &self,
        Parameters(args): Parameters<coredump_client::RestoreArgs>,
    ) -> CallToolResult {
        script_tool(coredump_client::restore_breakpoints(mcp_client!(self), args).await)
    }

    #[tool(
        description = "Capture and save a process snapshot. Optional dotted fields, tid, and frames filter the response."
    )]
    async fn snapshot(&self, Parameters(args): Parameters<CaptureTool>) -> CallToolResult {
        tool_reply(
            mcp_client!(self)
                .snapshot(request(SnapshotRequest {
                    pid: args.pid.unwrap_or_default(),
                    run_id: args.run_id,
                    freeze: FreezeMode::from(args.freeze) as i32,
                    selection: requested(args.fields, args.tid, args.frames),
                }))
                .await,
        )
    }

    #[tool(description = "Query a saved snapshot by snapshot_id or breakpoint event_id.")]
    async fn snapshot_query(&self, Parameters(args): Parameters<QueryTool>) -> CallToolResult {
        tool_reply(
            mcp_client!(self)
                .query_snapshot(request(QuerySnapshotRequest {
                    snapshot_id: args.snapshot_id.unwrap_or_default(),
                    event_id: args.event_id,
                    selection: requested(args.fields, args.tid, args.frames),
                }))
                .await,
        )
    }
    #[tool(
        description = "Install a breakpoint or watchpoint by pid or run_id. Use tid to limit hits to one thread. Set execution breakpoints by address, symbol, or source file and line. Supply handler (for example $.onHit), rule_id, or inline rule_source. \
                       Example: export default function onHit(hit: BreakpointHit) { hit.emit('address', hit.address); }. \
                       Module variables persist per breakpoint. timeout_ms sets the per-hit budget. \
                       Return false to suppress the hit event and snapshot, or call hit.disable() to disarm after the hit. \
                       hit.memory(address, length).view is a native DataView: getUint32(offset) reads big-endian, \
                       getUint32(offset, true) reads little-endian. Use script_api with mode breakpoint for declarations. \
                       Without a rule, hits save snapshots. Callback errors and timeouts are reported and disarm the breakpoint."
    )]
    async fn breakpoint_set(&self, Parameters(args): Parameters<BreakpointArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => {
                document_tool(mcp_client!(self).install_breakpoint(request(message)).await)
            }
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Install execution or watch points, resume the target, and collect hits in one transaction. Supply run_id or a launch request."
    )]
    async fn breakpoint_workflow(
        &self,
        Parameters(mut args): Parameters<BreakpointWorkflowArgs>,
    ) -> CallToolResult {
        let mut client = mcp_client!(self);
        script_tool(async {
            if !(1..=32).contains(&args.points.len()) {
                return Err(aidbg::Diagnostic::new("INVALID_ARGUMENT", "provide 1–32 workflow points", None).into());
            }
            if args.timeout_ms.is_some_and(|ms| !(1..=10_000).contains(&ms))
                || args.per_hit_timeout_ms.is_some_and(|ms| !(1..=500).contains(&ms))
                || args.points.iter().any(|point| point.timeout_ms.is_some_and(|ms| !(1..=500).contains(&ms)))
            {
                return Err(aidbg::Diagnostic::new("INVALID_ARGUMENT", "timeout_ms must be in 1..=10000 and per-hit timeouts in 1..=500", None).into());
            }
            let owns_run = args.run.is_some();
            let run: Value = match (&args.run_id, args.run.take()) {
                (Some(id), None) => {
                    let reply = client.run_status(run_request(&aidbg::run::RunId { run_id: id.clone() })).await?;
                    serde_json::from_slice(&reply.into_inner().json)?
                }
                (None, Some(mut run)) => {
                    run.pause_at_entry = true;
                    let reply = client.run_target(request(rule_request(&run)?)).await?;
                    serde_json::from_slice(&reply.into_inner().json)?
                }
                _ => return Err(aidbg::Diagnostic::new("INVALID_ARGUMENT", "provide run_id or run", None).into()),
            };
            let run_id = run["run_id"].as_str().ok_or_else(|| io::Error::other("server did not return a run ID"))?.to_owned();
            let result: AidbgResult<Value> = async {
                let mut addresses = Vec::with_capacity(args.points.len());
                for point in &args.points {
                    let base = match (&point.address, &point.symbol, &point.module) {
                        (Some(address), None, None) => parse_address(address)?,
                        (None, Some(symbol), module) => {
                            let reply = client.search_symbols(request(SearchSymbolsRequest {
                                pid: 0, pattern: symbol.clone(), module: module.clone(),
                                target_id: None, run_id: Some(run_id.clone()), match_mode: SymbolMatch::Exact as i32, limit: Some(4096),
                            })).await?;
                            let document: Value = serde_json::from_slice(&reply.into_inner().json)?;
                            let execution = matches!(point.kind, RuleKind::Hardware | RuleKind::Software);
                            let mut matches = document["matches"].as_array().ok_or_else(|| io::Error::other("symbol search did not return matches"))?
                                .iter().filter(|row| !execution || row["kind"] == "text");
                            match (matches.next(), matches.next()) {
                                (Some(found), None) if document["truncated"] != true => parse_address(found["runtime_address"].as_str()
                                    .ok_or_else(|| io::Error::other("symbol has no runtime address"))?)?,
                                (None, _) if document["truncated"] != true => return Err(aidbg::Diagnostic::new("SYMBOL_NOT_FOUND", format!("symbol {symbol} is unavailable"), None).into()),
                                _ => return Err(aidbg::Diagnostic::new("AMBIGUOUS_SYMBOL", format!("symbol {symbol} is ambiguous across loaded locations"), Some("Specify module.")).into()),
                            }
                        }
                        _ => return Err(aidbg::Diagnostic::new("INVALID_ARGUMENT", "each workflow point requires an address or symbol with optional module", None).into()),
                    };
                    let offset = point.offset.as_deref().map(parse_address).transpose()?.unwrap_or_default();
                    addresses.push(base.checked_add(offset).ok_or_else(|| aidbg::Diagnostic::new("INVALID_ARGUMENT", "workflow address overflow", None))?);
                }
                let source = args.source(&addresses)?;
                let mut result = self.scripts.run(aidbg::script::RunRequest {
                    source, run_id: Some(run_id.clone()), target_id: None,
                    timeout_ms: args.timeout_ms, replay_points: Vec::new(),
                }).await?;
            if let (Some(ids), Some(events)) = (
                result["breakpoint_ids"].as_array(), result["return_value"].as_array(),
            ) {
                let points: Vec<_> = ids.iter().zip(&args.points).zip(addresses).enumerate()
                    .map(|(index, ((id, point), address))| {
                        let hits: Vec<_> = events.iter().filter(|event| event["breakpoint_id"] == *id).collect();
                        let complete = hits.iter().all(|event| {
                            event["callback"]["status"] == "complete" && event["resume_status"] == "resumed"
                        });
                        serde_json::json!({
                            "point": index, "breakpoint_id": id, "address": aidbg::hex(address),
                            "symbol": point.symbol, "observed_hits": hits.len(), "complete": complete,
                        })
                    }).collect();
                result["points"] = serde_json::json!(points);
            }
                Ok(result)
            }.await;
            if owns_run && !result.as_ref().is_ok_and(|report| report["status"] == "complete") {
                client.run_cancel(run_request(&aidbg::run::RunId { run_id: run_id.clone() })).await?;
            }
            let mut result = result?;
            result["run_id"] = run_id.into();
            Ok(result)
        }.await)
    }

    #[tool(
        description = "Change a breakpoint address or named rule while preserving its ID and events."
    )]
    async fn breakpoint_update(
        &self,
        Parameters(args): Parameters<BreakpointUpdateArgs>,
    ) -> CallToolResult {
        match args.message() {
            Ok(message) => {
                document_tool(mcp_client!(self).update_breakpoint(request(message)).await)
            }
            Err(error) => argument_error(error),
        }
    }

    #[tool(
        description = "Register a reusable TypeScript breakpoint rule by rule_id, or use mode exports to register named functions for breakpoint_set handler references such as $.onHit. \
                       Example: export default function onHit(hit: BreakpointHit) { if (hit.watch?.changed === false) return false; hit.emit('address', hit.address); }. \
                       Each breakpoint has independent module state and a timeout_ms budget. Use script_api with mode breakpoint for declarations."
    )]
    async fn rule_define(
        &self,
        Parameters(args): Parameters<aidbg::script::RuleDefine>,
    ) -> CallToolResult {
        match rule_request(&args) {
            Ok(message) => document_tool(mcp_client!(self).rule_define(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "List named breakpoint rules with their current revision and total callback hits, including hits whose events were suppressed."
    )]
    async fn rule_list(&self) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .rule_list(request(rpc::ScriptDocumentRequest { json: vec![] }))
                .await,
        )
    }

    #[tool(
        description = "Replace a named rule's TypeScript source across its attached breakpoints. A successful update starts fresh module state \
                       for each breakpoint and preserves breakpoint IDs and event history. A failed update leaves the previous revision active."
    )]
    async fn rule_update(
        &self,
        Parameters(args): Parameters<aidbg::script::RuleUpdate>,
    ) -> CallToolResult {
        match rule_request(&args) {
            Ok(message) => document_tool(mcp_client!(self).rule_update(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Delete a named rule after its referencing breakpoints have been removed."
    )]
    async fn rule_remove(
        &self,
        Parameters(args): Parameters<aidbg::script::RuleId>,
    ) -> CallToolResult {
        match rule_request(&args) {
            Ok(message) => document_tool(mcp_client!(self).rule_remove(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(description = "Remove a breakpoint or watchpoint from the server.")]
    async fn breakpoint_remove(&self, Parameters(args): Parameters<RemoveArgs>) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .remove_breakpoint(request(RemoveBreakpointRequest {
                    pid: args.pid.unwrap_or_default(),
                    run_id: args.run_id,
                    breakpoint_id: args.breakpoint_id,
                }))
                .await,
        )
    }

    #[tool(
        description = "Read recent breakpoint and watchpoint events and their saved snapshot IDs. Successful callbacks returning false are omitted. Errors and timeouts produce diagnostic events."
    )]
    async fn breakpoint_events(&self, Parameters(args): Parameters<EventsArgs>) -> CallToolResult {
        let result = mcp_client!(self)
            .breakpoint_events(request(BreakpointEventsRequest {
                breakpoint_id: args.breakpoint_id,
                after_event_id: args.after_event_id,
            }))
            .await;
        let mut document: Value = match result {
            Ok(reply) => match serde_json::from_slice(&reply.into_inner().json) {
                Ok(document) => document,
                Err(error) => return result_error(error.into()),
            },
            Err(error) => return result_error(error.into()),
        };
        let mut text = Vec::new();
        if let Some(events) = document["events"].as_array_mut() {
            for event in events {
                let event_id = event["event_id"].clone();
                let breakpoint_id = event["breakpoint_id"].clone();
                if let Some(callback) = event.get_mut("callback").and_then(Value::as_object_mut)
                    && let Some(Value::Array(lines)) = callback.remove("output_text")
                {
                    let lines: Vec<_> = lines.iter().filter_map(Value::as_str).collect();
                    if !lines.is_empty() {
                        text.push(rmcp::model::ContentBlock::text(format!(
                            "Event {event_id}, breakpoint {breakpoint_id}\n{}",
                            lines.join("\n")
                        )));
                    }
                }
            }
        }
        let mut result = structured_document(document);
        result.content.extend(text);
        result
    }

    #[tool(
        description = "Sample live thread states and build a futex lock dependency graph for supplied glibc mutex addresses. An open core provides one captured sample and can use explicit waiter evidence."
    )]
    async fn observe_threads(
        &self,
        Parameters(args): Parameters<aidbg::script_observation::Request>,
    ) -> CallToolResult {
        script_tool(self.scripts.observe_threads(args).await)
    }

    #[tool(
        description = "Search ELF symbols in a live pid, run_id or open core target_id by exact name, glob or regex."
    )]
    async fn symbols(&self, Parameters(args): Parameters<SymbolArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => script_tool(self.scripts.symbols(message).await),
            Err(error) => result_error(error),
        }
    }

    #[tool(
        description = "Resolve a runtime address to its loaded module instance, ELF address and symbol."
    )]
    async fn resolve_address(&self, Parameters(args): Parameters<ResolveArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => script_tool(self.scripts.resolve(message).await),
            Err(error) => result_error(error),
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
            mcp_client!(self)
                .breakpoint_capabilities(request(BreakpointCapabilitiesRequest {
                    pid: args.pid,
                    run_id: args.run_id,
                }))
                .await,
        )
    }

    #[tool(
        description = "List installed breakpoints and watchpoints. Optionally select a PID or run ID."
    )]
    async fn breakpoint_list(
        &self,
        Parameters(args): Parameters<CapabilityArgs>,
    ) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .breakpoint_list(request(BreakpointCapabilitiesRequest {
                    pid: args.pid,
                    run_id: args.run_id,
                }))
                .await,
        )
    }

    #[tool(
        description = "Decode an instruction window around an address in a pid, run_id or target_id."
    )]
    async fn disassemble(&self, Parameters(args): Parameters<DisassembleArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => script_tool(self.scripts.disassemble(message).await),
            Err(error) => result_error(error),
        }
    }

    #[tool(
        description = "Find hexadecimal byte patterns in a live process or open core. The byte budget bounds scanning."
    )]
    async fn search_memory(
        &self,
        Parameters(args): Parameters<MemorySearchTool>,
    ) -> CallToolResult {
        script_tool(
            async {
                let request = rpc::SearchMemoryRequest {
                    target_id: args.target_id.unwrap_or_default(),
                    pid: args.pid,
                    run_id: args.run_id,
                    pattern: hex_bytes(&args.pattern)?,
                    start: args.start.as_deref().map(parse_address).transpose()?,
                    end: args.end.as_deref().map(parse_address).transpose()?,
                    limit: args.limit,
                    max_scan_bytes: args.max_scan_bytes,
                    alignment: args.alignment,
                    pointer_value: None,
                    instruction_references: false,
                    resume_from: None,
                };
                self.scripts.search_memory(request).await
            }
            .await,
        )
    }

    #[tool(
        description = "Read 1–65536 bytes from a live PID, run or open core. Returns hexadecimal bytes and the first unread address on a short read."
    )]
    async fn read_memory(&self, Parameters(args): Parameters<ReadMemoryArgs>) -> CallToolResult {
        match args.message() {
            Ok(request) => script_tool(self.scripts.read_memory(request).await),
            Err(error) => result_error(error),
        }
    }

    #[tool(
        description = "Compare two captured byte ranges with the same address and length. Pass before and after read_memory results. Returns changed offsets and the extent of comparable bytes."
    )]
    async fn memory_diff(&self, Parameters(args): Parameters<MemoryDiffTool>) -> CallToolResult {
        script_tool(args.compare())
    }

    #[tool(
        description = "Find stored pointer values or direct instruction references in core or live process memory."
    )]
    async fn xref(&self, Parameters(args): Parameters<XrefTool>) -> CallToolResult {
        script_tool(
            async {
                let request = rpc::SearchMemoryRequest {
                    target_id: args.target_id.unwrap_or_default(),
                    pid: args.pid,
                    run_id: args.run_id,
                    pattern: Vec::new(),
                    start: args.start.as_deref().map(parse_address).transpose()?,
                    end: args.end.as_deref().map(parse_address).transpose()?,
                    limit: args.limit,
                    max_scan_bytes: args.max_scan_bytes,
                    alignment: args.alignment,
                    pointer_value: Some(parse_address(&args.address)?),
                    instruction_references: args.instruction_references,
                    resume_from: args.resume_from.as_deref().map(parse_address).transpose()?,
                };
                self.scripts.search_memory(request).await
            }
            .await,
        )
    }

    #[tool(
        description = "Follow bounded 64-bit little-endian pointer reads in a pid, run_id or target_id. Each offset is added before dereferencing."
    )]
    async fn pointer_chain(
        &self,
        Parameters(args): Parameters<PointerChainTool>,
    ) -> CallToolResult {
        script_tool(
            async {
                let request = rpc::PointerChainRequest {
                    target_id: args.target_id.unwrap_or_default(),
                    pid: args.pid,
                    run_id: args.run_id,
                    base: parse_address(&args.base)?,
                    offsets: args.offsets,
                };
                self.scripts.pointer_chain(request).await
            }
            .await,
        )
    }

    #[tool(description = "Sample user-space hotspots or call stacks with Linux perf events.")]
    async fn perf(&self, Parameters(args): Parameters<PerfArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(mcp_client!(self).profile(request(message)).await),
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
                mcp_client!(self)
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
            mcp_client!(self)
                .symbol_override(override_request(OverrideAction::RemoveId(args.id)))
                .await,
        )
    }

    #[tool(description = "List debugger-local symbol overrides and their scopes.")]
    async fn symbol_override_list(&self) -> CallToolResult {
        document_tool(
            mcp_client!(self)
                .symbol_override(override_request(OverrideAction::List(true)))
                .await,
        )
    }

    #[tool(
        description = "Read a DWARF-backed C/C++ expression by pid, run_id or core target_id. For a run or core, pass expressions to read several values together. Use tid and frame_index to select a frame. Values stored in memory expose result.address."
    )]
    async fn inspect(&self, Parameters(args): Parameters<InspectArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => script_tool(self.scripts.inspect(message).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Compare a live data range after each step in a bounded user-space PC window."
    )]
    async fn watch_step(&self, Parameters(args): Parameters<WatchStepArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(mcp_client!(self).step_watch(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Execute a native scalar function in the live target. It can change memory, perform I/O, or affect other processes. These side effects can persist after return or error. Requires explicit consent."
    )]
    async fn target_call(&self, Parameters(args): Parameters<TargetCallArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(mcp_client!(self).target_call(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(description = "Assemble instructions with Keystone for the server architecture.")]
    async fn assemble(&self, Parameters(args): Parameters<AssembleArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => document_tool(mcp_client!(self).assemble(request(message)).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Plan an offline patch and check original instruction boundaries with Capstone."
    )]
    async fn plan_patch(&self, Parameters(args): Parameters<PatchArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => script_tool(self.scripts.patch(message).await),
            Err(e) => argument_error(e),
        }
    }

    #[tool(
        description = "Simulate copied code, registers and memory with Unicorn, with optional watchpoints and object bounds probes."
    )]
    async fn emulate(&self, Parameters(args): Parameters<EmulateArgs>) -> CallToolResult {
        match args.message() {
            Ok(message) => script_tool(self.scripts.emulate(message).await),
            Err(e) => argument_error(e),
        }
    }
}

#[tokio::main]
async fn main() -> AidbgResult<ExitCode> {
    let cli = Cli::parse();
    let endpoint = rpc::endpoint(cli.socket.as_deref(), cli.endpoint.as_deref())?;
    if matches!(
        cli.command,
        Command::ScriptApi(_)
            | Command::ScriptCheck(_)
            | Command::ScriptRun(_)
            | Command::CoreOpen(_)
            | Command::CoreClose(_)
            | Command::ReadMemory(_)
    ) {
        return script_client::cli(cli.command, endpoint.map(rpc::connect_lazy)).await;
    }
    if matches!(cli.command, Command::Mcp) {
        let mcp = Mcp {
            scripts: script_client::Client::new(endpoint.map(rpc::connect_lazy)),
        };
        mcp.serve(rmcp::transport::stdio()).await?.waiting().await?;
        return Ok(ExitCode::SUCCESS);
    }
    let endpoint = endpoint
        .ok_or_else(|| io::Error::other("--socket or --endpoint is required for this command"))?;
    let mut client = rpc::connect(endpoint).await?;
    let reply = match cli.command {
        Command::Run(args) => {
            let json = serde_json::to_vec(&args.message()?)?;
            tokio::select! {
                reply = client.run_target(Request::new(rpc::ScriptDocumentRequest { json })) => reply?,
                result = tokio::signal::ctrl_c() => {
                    result?;
                    return Ok(ExitCode::from(130));
                }
                result = terminate() => {
                    result?;
                    return Ok(ExitCode::from(143));
                }
            }
        }
        Command::RunStatus(id) => client.run_status(run_request(&id)).await?,
        Command::RunList => client.run_list(request(rpc::ScriptDocumentRequest { json: vec![] })).await?,
        Command::RunPause(id) => client.run_pause(run_request(&id)).await?,
        Command::RunContinue(id) => client.run_continue(run_request(&id)).await?,
        Command::RunCancel(id) => client.run_cancel(run_request(&id)).await?,
        Command::Step(args) => client.step_run(request(args.message(rpc::step_run_request::Mode::Step))).await?,
        Command::Next(args) => client.step_run(request(args.message(rpc::step_run_request::Mode::Next))).await?,
        Command::StepOut(args) => client.step_run(request(args.message(rpc::step_run_request::Mode::Out))).await?,
        Command::Snapshot(args) => return snapshot_cli(client, args).await,
        Command::ExportBundle(args) => {
            let summary = coredump_client::export_bundle(client, args).await?;
            println!("{}", serde_json::to_string(&summary)?);
            return Ok(ExitCode::SUCCESS);
        }
        Command::RestoreBreakpoints(args) => {
            let summary = coredump_client::restore_breakpoints(client, args).await?;
            println!("{}", serde_json::to_string(&summary)?);
            return Ok(ExitCode::SUCCESS);
        }
        Command::Coredump(args) => {
            let summary = tokio::select! {
                result = save_coredump(client, args) => result?,
                result = tokio::signal::ctrl_c() => {
                    result?;
                    return Ok(ExitCode::from(130));
                }
                result = terminate() => {
                    result?;
                    return Ok(ExitCode::from(143));
                }
            };
            let mut out = io::stdout().lock();
            serde_json::to_writer(&mut out, &summary)?;
            writeln!(out)?;
            out.flush()?;
            return Ok(ExitCode::SUCCESS);
        }
        Command::CoreRetain(args) => {
            println!("{}", serde_json::to_string(&coredump_client::retain_core(client, args).await?)?);
            return Ok(ExitCode::SUCCESS);
        }
        Command::Breakpoint(command) => match command {
            BreakpointCommand::Set(args) => {
                client.install_breakpoint(request(args.message()?)).await?
            }
            BreakpointCommand::Update(args) => {
                client.update_breakpoint(request(args.message()?)).await?
            }
            BreakpointCommand::Remove(args) => {
                client
                    .remove_breakpoint(request(RemoveBreakpointRequest {
                        pid: args.pid.unwrap_or_default(),
                        run_id: args.run_id,
                        breakpoint_id: args.breakpoint_id,
                    }))
                    .await?
            }
            BreakpointCommand::Capabilities(args) => {
                client
                    .breakpoint_capabilities(request(BreakpointCapabilitiesRequest {
                        pid: args.pid,
                        run_id: args.run_id,
                    }))
                    .await?
            }
            BreakpointCommand::List(args) => {
                client.breakpoint_list(request(BreakpointCapabilitiesRequest {
                    pid: args.pid, run_id: args.run_id,
                })).await?
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
        Command::Symbols(args) => client.search_symbols(request(args.message()?)).await?,
        Command::Resolve(args) => client.resolve_address(request(args.message()?)).await?,
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
        Command::Mcp
        | Command::ScriptApi(_)
        | Command::ScriptCheck(_)
        | Command::ScriptRun(_)
        | Command::CoreOpen(_)
        | Command::CoreClose(_)
        | Command::ReadMemory(_) => unreachable!(),
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

#[cfg(unix)]
async fn terminate() -> io::Result<()> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?
        .recv()
        .await;
    Ok(())
}

#[cfg(windows)]
async fn terminate() -> io::Result<()> {
    tokio::signal::windows::ctrl_break()?.recv().await;
    Ok(())
}
