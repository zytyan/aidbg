use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RunRequest {
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    /// Environment overrides on the server.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Input text followed by EOF. The default is empty input.
    pub stdin: Option<String>,
    /// Return a run ID with the target stopped at the initial exec event.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pause_at_entry: bool,
    /// Save a retained core at the process exit stop, while memory is still readable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exit_coredump: bool,
    pub cwd: Option<PathBuf>,
    pub signal_source: Option<String>,
    pub timeout_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub detach: bool,
}

#[derive(Deserialize, Serialize, JsonSchema, clap::Args)]
pub struct RunId {
    #[arg(long)]
    pub run_id: String,
}
