use aidbg::{Result, rpc::*};
use clap::Parser;
use rmcp::{
    ServiceExt, handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tonic::{Request, metadata::AsciiMetadataValue};

const API_URI: &str = "aidbg://debugger.d.ts";

#[derive(Parser)]
#[command(about = "Expose the aidbg debugger over MCP stdio", version = aidbg::BUILD_VERSION)]
struct Args {
    #[arg(
        long,
        conflicts_with = "endpoint",
        required_unless_present = "endpoint"
    )]
    socket: Option<PathBuf>,
    #[arg(long)]
    endpoint: Option<String>,
    /// Use the same token to reconnect within 30 seconds.
    #[arg(long)]
    session: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
struct RunArgs {
    path: String,
    #[serde(default)]
    arg: Vec<String>,
}
#[derive(Deserialize, JsonSchema)]
struct AttachArgs {
    pid: i32,
}
#[derive(Deserialize, JsonSchema)]
struct ScriptArgs {
    src: String,
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

#[derive(Clone)]
struct Mcp {
    client: Client,
    session: AsciiMetadataValue,
}

impl Mcp {
    fn request<T>(&self, value: T) -> Request<T> {
        let mut request = Request::new(value);
        request
            .metadata_mut()
            .insert("aidbg-session", self.session.clone());
        request
    }
}

impl rmcp::ServerHandler for Mcp {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        rmcp::model::ServerConfig::new(rmcp::model::ServerCapabilities::builder().enable_tools().enable_resources().build())
            .with_server_info(rmcp::model::Implementation::new("aidbg", aidbg::BUILD_VERSION))
            .with_instructions("Select a target with run, attach or core_open. Use script_run for TypeScript debugging. Inspect paused_threads, waiting_inputs and running_scripts on every tool response.")
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
                Self::tool_router().list_all(),
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
        ]))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::ReadResourceResponse, rmcp::ErrorData> {
        if request.uri != API_URI {
            return Err(rmcp::ErrorData::invalid_params("unknown resource", None));
        }
        Ok(
            rmcp::model::ReadResourceResult::new(vec![rmcp::model::ResourceContents::text(
                include_str!("../docs/debugger.d.ts"),
                API_URI,
            )])
            .into(),
        )
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> std::result::Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        Self::tool_router()
            .call(rmcp::handler::server::tool::ToolCallContext::new(
                self, request, context,
            ))
            .await
    }
}

fn reply(
    response: std::result::Result<tonic::Response<ToolReply>, tonic::Status>,
) -> CallToolResult {
    let result = match response {
        Ok(response) => response.into_inner(),
        Err(error) => return CallToolResult::structured_error(json!({"error":error.message()})),
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
            "Target threads are paused by the debugger. Use dbg.resume(tid) to resume, or dbg.thread(tid).passToTarget(...) to handle a pending signal.",
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
        CallToolResult::structured_error(document)
    } else {
        CallToolResult::structured(document)
    }
}

#[tool_router]
impl Mcp {
    #[tool(description = "Run a program on the debugger server and stop at exec.")]
    async fn run(&self, Parameters(args): Parameters<RunArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .run(self.request(RunProcessRequest {
                    path: args.path,
                    arg: args.arg,
                }))
                .await,
        )
    }

    #[tool(description = "Attach to a Linux process on the debugger server.")]
    async fn attach(&self, Parameters(args): Parameters<AttachArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .attach(self.request(AttachRequest { pid: args.pid }))
                .await,
        )
    }

    #[tool(
        description = "Type-check and run a TypeScript module. Read aidbg://debugger.d.ts for the API. Exports are available on $ across script calls."
    )]
    async fn script_run(&self, Parameters(args): Parameters<ScriptArgs>) -> CallToolResult {
        reply(
            self.client
                .clone()
                .script_run(self.request(RunScriptRequest { src: args.src }))
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

    #[tool(description = "Deliver data to a handler waiting in console.waitInput.")]
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

    #[tool(description = "Reject a handler's console.waitInput promise with a message.")]
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
                .snapshot(self.request(SessionSnapshotRequest { tid: args.tid }))
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

    #[tool(description = "List processes on the debugger server.")]
    async fn ps(&self) -> CallToolResult {
        reply(
            self.client
                .clone()
                .ps(self.request(ProcessListRequest {}))
                .await,
        )
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let endpoint = endpoint(args.socket.as_deref(), args.endpoint.as_deref())?
        .expect("clap validates the endpoint");
    let session = args.session.map_or_else(
        || {
            let file = tempfile::Builder::new()
                .prefix("session-")
                .rand_bytes(32)
                .tempfile()?;
            Ok::<_, std::io::Error>(
                file.path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            )
        },
        Ok,
    )?;
    let mcp = Mcp {
        client: connect_lazy(endpoint),
        session: session.parse()?,
    };
    let heartbeat = mcp.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let mut request = heartbeat.request(HeartbeatRequest {});
            request.set_timeout(Duration::from_secs(2));
            let _ = heartbeat.client.clone().heartbeat(request).await;
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
