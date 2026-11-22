use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Request {
    pub target_id: Option<String>,
    pub pid: Option<i32>,
    pub run_id: Option<String>,
    pub samples: Option<u32>,
    pub interval_ms: Option<u32>,
    #[serde(default)]
    pub locks: Vec<Lock>,
    #[serde(default)]
    pub waits: Vec<Wait>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Lock {
    /// Futex word address in decimal or hexadecimal.
    pub address: String,
    /// Byte offset to the glibc mutex owner TID. Defaults to 8.
    pub owner_offset: Option<u32>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Wait {
    pub tid: i32,
    pub address: String,
}
