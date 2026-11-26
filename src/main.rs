use aidbg::{Result, rpc::*, script_types};
use clap::{Parser, Subcommand};
use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tonic::{Request, metadata::AsciiMetadataValue};

mod mcp_text;

const API_URI: &str = "aidbg://debugger.d.ts";
const NODE_API_URI: &str = "aidbg://node.d.ts";

const START_SERVER: &str =
    "Start aidbg-server on the Linux debugging host. For a local Unix socket:

  state_dir=\"$(mktemp -d)\"
  aidbg-server --state-dir \"$state_dir\" --socket \"$state_dir/aidbg.sock\"

For TCP (including Windows clients), use a trusted network or SSH forwarding:

  state_dir=\"$(mktemp -d)\"
  aidbg-server --state-dir \"$state_dir\" --listen HOST:PORT

Configure the MCP host to run aidbg with args [\"mcp\"]. Then call the connect tool
with socket set to the absolute socket path or endpoint set to http://HOST:PORT.
Use the optional session token to reconnect to the same debugging session within 30 seconds.";

#[derive(Parser)]
#[command(about = "Expose the aidbg debugger over MCP stdio", after_help = START_SERVER)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the MCP stdio process.
    #[command(after_help = START_SERVER)]
    Mcp,
}

#[derive(Deserialize, JsonSchema)]
struct ConnectArgs {
    #[schemars(description = "Absolute path to the server Unix socket")]
    socket: Option<PathBuf>,
    #[schemars(description = "TCP endpoint in the form http://HOST:PORT")]
    endpoint: Option<String>,
    #[schemars(
        description = "Session token to reuse within 30 seconds (24–128 ASCII letters, digits, hyphens, or underscores)"
    )]
    session: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct RunArgs {
    path: String,
    #[serde(default)]
    arg: Vec<String>,
    /// Keep the target paused after launch.
    #[serde(default)]
    pause: bool,
}
#[derive(Deserialize, JsonSchema)]
struct AttachArgs {
    pid: i32,
    /// Keep the target paused after attach.
    #[serde(default)]
    pause: bool,
}
#[derive(Deserialize, JsonSchema)]
struct GdbArgs {
    command: String,
}

#[derive(Deserialize, JsonSchema)]
struct ScriptArgs {
    src: String,
    /// Optional completion wait in milliseconds, up to 300000.
    wait_ms: Option<u32>,
    /// Optionally launch a new target before checking and executing the script.
    run: Option<RunArgs>,
}
#[derive(Deserialize, JsonSchema)]
struct ScriptWaitArgs {
    script_id: u64,
    /// Completion wait in milliseconds, up to 300000. Defaults to 5000.
    wait_ms: Option<u32>,
}
#[derive(Deserialize, JsonSchema)]
struct CoreArgs {
    path: String,
    executable: Option<String>,
    debug_symbols: Option<String>,
}
#[derive(Deserialize, JsonSchema)]
struct InputArgs {
    handler: String,
    data: String,
}
#[derive(Deserialize, JsonSchema)]
struct InterruptArgs {
    handler: String,
    msg: Option<String>,
}
#[derive(Deserialize, JsonSchema)]
struct SnapshotArgs {
    tid: Option<i32>,
    /// Pause budget in milliseconds, 0 through 1000. Zero samples existing stops.
    stop_timeout_ms: Option<u32>,
    #[serde(default)]
    context: bool,
}
#[derive(Deserialize, JsonSchema)]
struct PsArgs {
    #[serde(default)]
    #[schemars(description = "List individual threads and their TIDs")]
    threads: bool,
    #[schemars(
        description = "Case-insensitive substring in the PID, process name or command line"
    )]
    pattern: Option<String>,
    limit: Option<u32>,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    #[schemars(description = "Choose pid, ppid, name, threads, tid or args")]
    fields: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
struct SyscallArgs {
    id: Option<u64>,
    name: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ForkPolicy {
    Parent,
    Child,
    Both,
}

#[derive(Deserialize, JsonSchema)]
struct ForkPolicyArgs {
    mode: ForkPolicy,
}

#[derive(Deserialize, JsonSchema)]
struct PerfArgs {
    pid: i32,
    #[serde(default)]
    hotspot: bool,
    #[serde(default)]
    stack: bool,
    duration_ms: Option<u32>,
    frequency_hz: Option<u32>,
    tid: Option<i32>,
}

#[derive(Clone, Default)]
struct Mcp {
    connection: Arc<Mutex<Option<Connection>>>,
}

#[derive(Clone)]
struct Connection {
    client: Client,
    session: AsciiMetadataValue,
    presentation: Arc<Mutex<mcp_text::Presentation>>,
    text_output: bool,
}

impl Connection {
    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert("aidbg-session", self.session.clone());
        if self.text_output {
            request
                .metadata_mut()
                .insert("aidbg-presentation", "text".parse().unwrap());
        }
        request
    }

    async fn heartbeat(&self) -> std::result::Result<(), tonic::Status> {
        let mut request = self.request(HeartbeatRequest {});
        request.set_timeout(Duration::from_secs(2));
        self.client.clone().heartbeat(request).await?;
        Ok(())
    }
}

impl rmcp::ServerHandler for Mcp {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(rmcp::model::ServerCapabilities::builder().enable_tools().enable_resources().build())
            .with_server_info(rmcp::model::Implementation::new("aidbg", aidbg::BUILD_VERSION))
            .with_instructions("Call docs for the script API and connect to select a debugger server. Use run and attach to debug programs, and use a shell tool for shell commands. Use script_run for TypeScript debugging. Only top-level script code runs automatically. Inspect paused_threads, waiting_inputs and running_scripts on every tool response.")
    }

    fn list_tools(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<
        Output = std::result::Result<rmcp::model::ListToolsResult, rmcp::ErrorData>,
    > + Send
    + '_ {
        async {
            Ok(rmcp::model::ListToolsResult::with_all_items(
                Self::tool_router()
                    .list_all()
                    .into_iter()
                    .chain(Connection::tool_router().list_all())
                    .map(|mut tool| {
                        let schema = Arc::make_mut(&mut tool.input_schema);
                        if !schema.get("properties").is_some_and(Value::is_object) {
                            schema.insert("properties".into(), json!({}));
                        }
                        schema.get_mut("properties").unwrap().as_object_mut().unwrap().insert(
                            "output_format".into(),
                            json!({"type":"string","enum":["text","structured"],"default":"text",
                                "description":"Select structured output explicitly for existing machine clients."}),
                        );
                        tool
                    })
                    .collect(),
            ))
        }
    }

    async fn list_resources(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ListResourcesResult, rmcp::ErrorData> {
        Ok(rmcp::model::ListResourcesResult::with_all_items(vec![
            rmcp::model::Resource::new(API_URI, "aidbg TypeScript API")
                .with_mime_type("text/plain"),
            rmcp::model::Resource::new(NODE_API_URI, "aidbg file and path module APIs")
                .with_mime_type("text/plain"),
        ]))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        let text = match request.uri.as_str() {
            API_URI => script_types::DEBUGGER_DECLARATIONS,
            NODE_API_URI => script_types::NODE_DECLARATIONS,
            _ => return Err(rmcp::ErrorData::invalid_params("unknown resource", None)),
        };
        Ok(
            rmcp::model::ReadResourceResult::new(vec![rmcp::model::ResourceContents::text(
                text,
                request.uri,
            )])
            .into(),
        )
    }

    async fn call_tool(
        &self,
        mut request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        use rmcp::handler::server::tool::ToolCallContext;
        let format = request
            .arguments
            .as_mut()
            .and_then(|args| args.remove("output_format"));
        let structured = match format.as_ref().and_then(Value::as_str) {
            Some("structured") => true,
            Some("text") => false,
            None if format.is_none() => false,
            _ => return Ok(mcp_text::error("output_format must be text or structured").into()),
        };
        let name = request.name.clone();
        let source = request
            .arguments
            .as_ref()
            .and_then(|args| args.get("src"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let path = request
            .arguments
            .as_ref()
            .and_then(|args| {
                if name == "script_run" {
                    args.get("run").and_then(|run| run.get("path"))
                } else {
                    args.get("path")
                }
            })
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut connection = self.connection.lock().await.clone();
        if let Some(connection) = &mut connection {
            connection.text_output = !structured;
        }
        let response = if matches!(name.as_ref(), "connect" | "docs") {
            Self::tool_router()
                .call(ToolCallContext::new(self, request, context))
                .await?
        } else if let Some(connection) = &connection {
            Connection::tool_router()
                .call(ToolCallContext::new(connection, request, context))
                .await?
        } else {
            mcp_text::document_error(json!({
                "error": "Call connect with a server socket or endpoint first."
            }))
            .into()
        };
        let rmcp::model::CallToolResponse::Complete(result) = response else {
            return Ok(response);
        };
        let rendered = if let Some(connection) = &connection
            && !matches!(name.as_ref(), "connect" | "docs")
        {
            connection.presentation.lock().await.render(
                result,
                &name,
                source.as_deref(),
                path.as_deref(),
                structured,
            )
        } else {
            mcp_text::Presentation::default().render(
                result,
                &name,
                source.as_deref(),
                path.as_deref(),
                structured,
            )
        };
        Ok(rendered.into())
    }
}

#[tool_router]
impl Mcp {
    #[tool(description = "Show script entry semantics and the full TypeScript declarations for script_run.")]
    async fn docs(&self) -> CallToolResult {
        mcp_text::document(json!({
            "instructions": "script_run executes the module's top-level code. Named exports from successful scripts are available on $ to subsequent scripts in the same session. Switching targets clears these exports. The declarations describe the initial session. Types inferred from target DWARF and prior script exports are added during compilation. Use run and attach for debugging and a shell tool for shell commands. The default fork policy follows the parent.",
            "declarations": script_types::declarations(),
            "modules": script_types::NODE_DECLARATIONS,
            "full_api": API_URI,
        }))
    }

    #[tool(
        description = "Connect to an aidbg-server. Supply exactly one of socket or endpoint. Reuse the returned session token to reconnect to the same session."
    )]
    async fn connect(&self, Parameters(args): Parameters<ConnectArgs>) -> CallToolResult {
        match self.open_connection(args).await {
            Ok(result) => mcp_text::document(result),
            Err(error) => mcp_text::document_error(json!({"error": error.to_string()})),
        }
    }

    async fn open_connection(&self, args: ConnectArgs) -> Result<Value> {
        if args.socket.is_some() == args.endpoint.is_some() {
            return Err("provide exactly one of socket or endpoint".into());
        }
        let endpoint = endpoint(args.socket.as_deref(), args.endpoint.as_deref())?
            .expect("exactly one address was provided");
        let session = match args.session {
            Some(session) => session,
            None => {
                let file = tempfile::Builder::new()
                    .prefix("session-")
                    .rand_bytes(32)
                    .tempfile()?;
                file.path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            }
        };
        let mut active = self.connection.lock().await;
        let connection = Connection {
            client: connect(endpoint).await?,
            session: session.parse()?,
            presentation: Arc::default(),
            text_output: false,
        };
        connection.heartbeat().await?;
        *active = Some(connection);

        let mut result = json!({"status": "connected", "session": session});
        if let Some(socket) = args.socket {
            result["socket"] = json!(socket);
        }
        if let Some(endpoint) = args.endpoint {
            result["endpoint"] = json!(endpoint);
        }
        Ok(result)
    }
}

fn reply(
    response: std::result::Result<tonic::Response<ToolReply>, tonic::Status>,
) -> CallToolResult {
    let result = match response {
        Ok(response) => response.into_inner(),
        Err(error) => return mcp_text::document_error(json!({"error":error.message()})),
    };
    let inputs: Vec<_> = result
        .waiting_inputs
        .iter()
        .map(|input| {
            let mut row = json!({"handler":input.handler,"tid":input.tid});
            if let Ok(payload) = serde_json::from_slice::<Value>(&input.payload_json) {
                row["payload"] = payload;
            }
            row
        })
        .collect();
    let output: Vec<_> = result.script_output.iter().map(|entry| {
        json!({"script_id":entry.script_id, "value":serde_json::from_slice::<Value>(&entry.json).unwrap_or(Value::Null)})
    }).collect();
    let mut prompts = Vec::new();
    if !result.paused_threads.is_empty() {
        prompts.push(
            "Target threads are paused by the debugger. Use dbg.resumeThread(tid) to resume, or dbg.thread(tid).passToTarget(...) to handle a pending signal.",
        );
    }
    if !inputs.is_empty() {
        prompts.push("Scripts are waiting for input. Use send_input or interrupt_input with the listed handler.");
    }
    if !result.running_scripts.is_empty() {
        prompts.push("Scripts are still running. Each tool call reports their current state and any new output.");
    }
    if result.output_dropped {
        prompts.push("Older script output was dropped after the 1 MiB buffer filled.");
    }
    let waiting_events =
        serde_json::from_slice::<Value>(&result.waiting_events_json).unwrap_or_else(|_| json!([]));
    let signals =
        serde_json::from_slice::<Value>(&result.signals_json).unwrap_or_else(|_| json!([]));
    if result.event_queue_full {
        prompts.push(
            "The target event queue is full. Consume queued events before waiting for fresh stops.",
        );
    }
    let document = json!({
        "result":serde_json::from_slice::<Value>(&result.result_json).unwrap_or(Value::Null),
        "error":result.error,
        "paused_threads":result.paused_threads,
        "paused_stops":serde_json::from_slice::<Value>(&result.paused_stops_json).unwrap_or_else(|_| json!([])),
        "waiting_inputs":inputs,
        "running_scripts":result.running_scripts,
        "waiting_events":waiting_events,
        "signals":signals,
        "process_output":serde_json::from_slice::<Value>(&result.process_output_json).unwrap_or(Value::Null),
        "pending_events":result.pending_events,
        "event_queue_full":result.event_queue_full,
        "output":output,
        "output_dropped":result.output_dropped,
        "target_error":result.target_error,
        "prompts":prompts,
    });
    if result.error.is_some() {
        mcp_text::document_error(document)
    } else {
        mcp_text::document(document)
    }
}

#[tool_router]
impl Connection {
    #[tool(
        description = "List native Linux syscall IDs and six ordered parameter slots. Optionally filter by ID or name."
    )]
    async fn syscall_table(&self, Parameters(args): Parameters<SyscallArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .syscall_table(self.request(SyscallTableRequest {
                    id: args.id,
                    name: args.name,
                }))
                .await,
        )
    }

    #[tool(
        description = "Launch a program under the debugger. Set pause to true to stop at exec. Use a shell tool for shell commands."
    )]
    async fn run(&self, Parameters(args): Parameters<RunArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .run(self.request(RunProcessRequest {
                    path: args.path,
                    arg: args.arg,
                    pause: args.pause,
                }))
                .await,
        )
    }

    #[tool(description = "Read the current debugger session and target state without pausing it.")]
    async fn status(&self) -> CallToolResult {
        reply(
            self.client
                .clone()
                .status(self.request(HeartbeatRequest {}))
                .await,
        )
    }

    #[tool(
        description = "Attach the debugger to an existing Linux process. By default fork tracing follows the parent."
    )]
    async fn attach(&self, Parameters(args): Parameters<AttachArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .attach(self.request(AttachRequest {
                    pid: args.pid,
                    pause: args.pause,
                }))
                .await,
        )
    }

    #[tool(description = "Execute a supported GDB command against the current aidbg session.")]
    async fn gdb(&self, Parameters(args): Parameters<GdbArgs>) -> CallToolResult {
        if args.command.is_empty() || args.command.len() > 4096 {
            return mcp_text::document_error(
                json!({"error":"expected a GDB command of 1–4096 bytes"}),
            );
        }
        reply(
            self.client
                .clone()
                .script_run(self.request(RunScriptRequest {
                    src: format!("await fmt.gdb({});", json!(args.command)),
                    wait_ms: 5_000,
                    run: None,
                }))
                .await,
        )
    }

    #[tool(
        description = "Type-check a TypeScript module and execute its top-level code. Exports are available on $ across calls. See docs for the API."
    )]
    async fn script_run(&self, Parameters(args): Parameters<ScriptArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .script_run(self.request(RunScriptRequest {
                    src: args.src,
                    wait_ms: args.wait_ms.unwrap_or(if self.text_output {
                        100
                    } else if args.run.is_some() {
                        5000
                    } else {
                        0
                    }),
                    run: args.run.map(|run| RunProcessRequest {
                        path: run.path,
                        arg: run.arg,
                        pause: run.pause,
                    }),
                }))
                .await,
        )
    }

    #[tool(
        description = "Wait for a submitted script by ID and collect its current output. A wait timeout leaves the script running."
    )]
    async fn script_wait(&self, Parameters(args): Parameters<ScriptWaitArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .script_wait(self.request(WaitScriptRequest {
                    script_id: args.script_id,
                    wait_ms: args.wait_ms.unwrap_or(5000),
                }))
                .await,
        )
    }

    #[tool(description = "Open an ELF core (plain or zstd) using paths on the server.")]
    async fn core_open(&self, Parameters(args): Parameters<CoreArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .core_open(self.request(OpenCoreRequest {
                    path: args.path,
                    executable: args.executable,
                    debug_symbols: args.debug_symbols,
                }))
                .await,
        )
    }

    #[tool(description = "Deliver data to a handler waiting for an ask response.")]
    async fn send_input(&self, Parameters(args): Parameters<InputArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .send_input(self.request(SendInputRequest {
                    handler: args.handler,
                    data: args.data,
                }))
                .await,
        )
    }

    #[tool(description = "Reject a handler's ask promise with a message.")]
    async fn interrupt_input(&self, Parameters(args): Parameters<InterruptArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .interrupt_input(self.request(InterruptInputRequest {
                    handler: args.handler,
                    msg: args.msg,
                }))
                .await,
        )
    }

    #[tool(
        description = "Read registers, stack frames, local variables and memory mappings of the active target."
    )]
    async fn snapshot(&self, Parameters(args): Parameters<SnapshotArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .snapshot(self.request(SessionSnapshotRequest {
                    tid: args.tid,
                    stop_timeout_ms: args.stop_timeout_ms,
                    context: args.context,
                }))
                .await,
        )
    }

    #[tool(description = "Sample a process. Select exactly one of hotspot or stack.")]
    async fn perf(&self, Parameters(args): Parameters<PerfArgs>) -> CallToolResult {
        let request = SessionProfileRequest {
            pid: args.pid,
            hotspot: args.hotspot,
            stack: args.stack,
            duration_ms: args.duration_ms,
            frequency_hz: args.frequency_hz,
            tid: args.tid,
        };
        reply(self.client.clone().perf(self.request(request)).await)
    }

    #[tool(description = "Set the active target's fork policy.")]
    async fn set_fork_policy(
        &self,
        Parameters(args): Parameters<ForkPolicyArgs>,
    ) -> CallToolResult {
        let mode = match args.mode {
            ForkPolicy::Parent => "parent",
            ForkPolicy::Child => "child",
            ForkPolicy::Both => "both",
        };
        reply(
            self.client
                .clone()
                .set_fork_policy(self.request(ForkPolicyRequest { mode: mode.into() }))
                .await,
        )
    }

    #[tool(
        description = "List processes. Use threads for individual TIDs and fields to include command lines."
    )]
    async fn ps(&self, Parameters(args): Parameters<PsArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .ps(self.request(ProcessListRequest {
                    threads: args.threads,
                    pattern: args.pattern,
                    limit: args.limit,
                    offset: args.offset,
                    fields: args.fields,
                }))
                .await,
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Mcp => serve_mcp().await,
    }
}

async fn serve_mcp() -> Result<()> {
    let mcp = Mcp::default();
    let heartbeat = mcp.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let active = heartbeat.connection.lock().await.clone();
            if let Some(active) = active {
                let _ = active.heartbeat().await;
            }
        }
    });
    let service = mcp.serve(rmcp::transport::stdio()).await?;
    tokio::select! {
        result = service.waiting() => { result?; }
        result = tokio::signal::ctrl_c() => { result?; }
    }
    task.abort();
    Ok(())
}
