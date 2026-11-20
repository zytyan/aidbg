use crate::Result;
use std::path::Path;
use tonic::transport::{Channel, Endpoint};

tonic::include_proto!("aidbg");

pub const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
pub const MAX_RPC: usize = MAX_DOCUMENT + 4096;
pub type Client = debugger_client::DebuggerClient<Channel>;

pub async fn connect(socket: &Path) -> Result<Client> {
    let path = socket
        .to_str()
        .ok_or_else(|| crate::error("socket path must be UTF-8"))?;
    if !socket.is_absolute() {
        return Err(crate::error("use an absolute socket path"));
    }
    let channel = Endpoint::try_from(format!("unix://{path}"))?
        .connect_timeout(std::time::Duration::from_secs(3))
        .connect()
        .await?;
    Ok(Client::new(channel)
        .max_decoding_message_size(MAX_RPC)
        .max_encoding_message_size(MAX_RPC))
}
