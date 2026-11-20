use aidbg::rpc::{self, Client, FreezeMode, QuerySnapshotRequest, SnapshotReply, SnapshotRequest};
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
use tonic::Request;

#[derive(Parser)]
#[command(about = "Connect to an aidbg snapshot server")]
struct Cli {
    #[arg(long)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture a live snapshot or query a stored snapshot by ID.
    Snapshot(SnapshotArgs),
    /// Expose snapshot tools over MCP stdio.
    Mcp,
}

#[derive(Args)]
struct SnapshotArgs {
    #[arg(long, required_unless_present = "from", conflicts_with = "from")]
    pid: Option<i32>,
    /// Query this saved snapshot ID instead of capturing a PID.
    #[arg(long)]
    from: Option<String>,
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
    let reply = if let Some(id) = args.from {
        client
            .query_snapshot(request(QuerySnapshotRequest {
                snapshot_id: id,
                selection,
            }))
            .await?
    } else {
        let mode = FreezeMode::from(args.freeze.unwrap_or_default());
        let pid = args
            .pid
            .ok_or_else(|| io::Error::other("expected --pid or --from"))?;
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
    Ok(if doc["status"] == "failed" {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
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
    snapshot_id: String,
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
    match result {
        Ok(reply) => match serde_json::from_slice::<Value>(&reply.into_inner().snapshot_json) {
            Ok(doc) if doc["status"] == "failed" => CallToolResult::structured_error(doc),
            Ok(doc) => CallToolResult::structured(doc),
            Err(e) => CallToolResult::structured_error(serde_json::json!({"error":e.to_string()})),
        },
        Err(e) => CallToolResult::structured_error(serde_json::json!({"error":e.message()})),
    }
}

#[tool_router(server_handler)]
impl Mcp {
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

    #[tool(
        description = "Query a previously saved snapshot by ID. This does not attach to the original process."
    )]
    async fn snapshot_query(&self, Parameters(args): Parameters<QueryTool>) -> CallToolResult {
        tool_reply(
            self.client
                .clone()
                .query_snapshot(request(QuerySnapshotRequest {
                    snapshot_id: args.snapshot_id,
                    selection: requested(args.fields, args.tid, args.frames),
                }))
                .await,
        )
    }
}

#[tokio::main]
async fn main() -> AidbgResult<ExitCode> {
    let cli = Cli::parse();
    let client = rpc::connect(&cli.socket).await?;
    match cli.command {
        Command::Snapshot(args) => snapshot_cli(client, args).await,
        Command::Mcp => {
            let mcp = Mcp { client }.serve(rmcp::transport::stdio()).await?;
            mcp.waiting().await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}
