use crate::Result;
use std::path::Path;
use tonic::transport::{Channel, Endpoint};

tonic::include_proto!("aidbg");

pub const MAX_DOCUMENT: usize = 16 * 1024 * 1024;
pub const MAX_RPC: usize = MAX_DOCUMENT + 4096;
pub type Client = debugger_client::DebuggerClient<Channel>;

#[cfg(unix)]
fn unix_endpoint(socket: &Path) -> Result<Endpoint> {
    let path = socket
        .to_str()
        .ok_or_else(|| crate::error("socket path must be UTF-8"))?;
    if !socket.is_absolute() {
        return Err(crate::error("use an absolute socket path"));
    }
    Ok(Endpoint::try_from(format!("unix://{path}"))?
        .connect_timeout(std::time::Duration::from_secs(3)))
}

pub fn endpoint(socket: Option<&Path>, tcp: Option<&str>) -> Result<Option<Endpoint>> {
    if let Some(tcp) = tcp {
        let endpoint = Endpoint::try_from(tcp.to_owned())?;
        let uri = endpoint.uri();
        let host = uri.host().unwrap_or_default();
        if uri.scheme_str() != Some("http")
            || host.is_empty()
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_unspecified())
            || uri.port_u16().is_none_or(|port| port == 0)
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
        {
            return Err(crate::error(
                "use endpoint http://HOST:PORT with a reachable server address",
            ));
        }
        return Ok(Some(
            endpoint.connect_timeout(std::time::Duration::from_secs(3)),
        ));
    }
    #[cfg(unix)]
    return socket.map(unix_endpoint).transpose();
    #[cfg(windows)]
    if socket.is_some() {
        Err(crate::error(
            "socket requires Linux. Use endpoint for a TCP connection.",
        ))
    } else {
        Ok(None)
    }
}

fn client(channel: Channel) -> Client {
    Client::new(channel)
        .max_decoding_message_size(MAX_RPC)
        .max_encoding_message_size(MAX_RPC)
}

pub async fn connect(endpoint: Endpoint) -> Result<Client> {
    Ok(client(endpoint.connect().await?))
}
