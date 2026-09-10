//! Local control RPC: a length-bounded frame protocol carrying JSON
//! requests over a localhost TCP socket. This is the surface the
//! `scone` CLI talks to (`status`, `submit_tx`, `lookup`,
//! `put_record`, `get_record`, `domain_info`).
//!
//! Wire format (both directions): `len: u32 BE || UTF-8 JSON || '\n'`,
//! one request per connection (connection-per-command keeps the
//! protocol stateless and trivial to bound).
//!
//! Security: bound to localhost by construction; every frame is
//! length-bounded before parsing; a malformed request yields a typed
//! error response, never a panic.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{NetworkError, Result};

/// Hard cap on a single RPC frame (request or response).
pub const MAX_RPC_LEN: usize = 512 * 1024;

/// Server-side read timeout.
pub const RPC_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Client-side timeout (longer: DHT queries can take several
/// round trips).
pub const RPC_CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Control request issued by the CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum RpcRequest {
    /// Relay status: tip, height, peers, domain count, mempool size.
    Status,
    /// Submit a signed transaction (canonical hex).
    SubmitTx { tx_hex: String },
    /// On-chain state of a domain name.
    Lookup { name: String },
    /// Publish a signed record in the DHT (canonical hex).
    PutRecord { record_hex: String },
    /// Resolve a record from the DHT and verify it against the chain.
    GetRecord { name: String },
    /// Rich exploration of a domain (M5): on-chain state plus, when
    /// a chain-valid record is locally cached, its decoded DNS
    /// records. Never hits the network.
    DomainInfo { name: String },
}

/// Control response returned to the CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RpcResponse {
    /// Success; `data` is a JSON value (shape per method).
    Ok { data: serde_json::Value },
    /// Failure with a human-readable message.
    Error { message: String },
}

impl RpcResponse {
    /// Builds an [`RpcResponse::Ok`].
    #[must_use]
    pub fn ok(data: serde_json::Value) -> Self {
        Self::Ok { data }
    }

    /// Builds an [`RpcResponse::Error`].
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }

    /// Unwraps `Ok`, mapping `Error` to [`NetworkError::Peer`].
    ///
    /// # Errors
    ///
    /// [`NetworkError::Peer`] carrying the server's message.
    pub fn into_result(self) -> Result<serde_json::Value> {
        match self {
            Self::Ok { data } => Ok(data),
            Self::Error { message } => Err(NetworkError::Peer(message)),
        }
    }
}

/// Reads one length-prefixed frame (bounded).
async fn read_message(stream: &mut TcpStream) -> Result<String> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_RPC_LEN {
        return Err(NetworkError::LimitExceeded("rpc message"));
    }
    let mut buffer = vec![0u8; len];
    stream.read_exact(&mut buffer).await?;
    while buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    String::from_utf8(buffer).map_err(|_| NetworkError::InvalidRpc("non-utf8 payload".into()))
}

/// Writes one length-prefixed frame.
async fn write_message(stream: &mut TcpStream, text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    let len =
        u32::try_from(bytes.len() + 1).map_err(|_| NetworkError::LimitExceeded("rpc message"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

/// Parses an [`RpcRequest`] from raw JSON text (strict).
///
/// # Errors
///
/// [`NetworkError::InvalidRpc`] on malformed JSON or unknown method.
pub fn parse_request(text: &str) -> Result<RpcRequest> {
    serde_json::from_str(text).map_err(|e| NetworkError::InvalidRpc(e.to_string()))
}

/// Serves one connection: read request → dispatch → write response.
///
/// `dispatch` is async so the handler can await deferred results
/// (DHT lookups).
///
/// # Errors
///
/// [`NetworkError`] on socket or timeout failures only — dispatch
/// errors are turned into [`RpcResponse::Error`] answers.
pub async fn serve_connection<F, Fut>(stream: &mut TcpStream, dispatch: F) -> Result<()>
where
    F: FnOnce(RpcRequest) -> Fut,
    Fut: std::future::Future<Output = RpcResponse>,
{
    let text = match tokio::time::timeout(RPC_READ_TIMEOUT, read_message(stream)).await {
        Ok(Ok(text)) => text,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(NetworkError::timeout("rpc read")),
    };
    let response = match parse_request(&text) {
        Ok(request) => dispatch(request).await,
        Err(e) => RpcResponse::error(e.to_string()),
    };
    let json = serde_json::to_string(&response)
        .map_err(|e| NetworkError::InvalidRpc(format!("serialize: {e}")))?;
    tokio::time::timeout(RPC_READ_TIMEOUT, write_message(stream, &json))
        .await
        .map_err(|_| NetworkError::timeout("rpc write"))??;
    Ok(())
}

/// Local RPC client used by the CLI.
#[derive(Debug, Clone)]
pub struct RpcClient {
    addr: SocketAddr,
}

impl RpcClient {
    /// Client for a relay RPC at `addr`.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// The address this client dials.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Sends one request and awaits the response.
    ///
    /// # Errors
    ///
    /// [`NetworkError::Io`] when the relay is unreachable — the CLI
    /// turns this into a clear "relay not running" message.
    pub async fn request(&self, request: RpcRequest) -> Result<RpcResponse> {
        let mut stream = tokio::time::timeout(RPC_CLIENT_TIMEOUT, TcpStream::connect(self.addr))
            .await
            .map_err(|_| NetworkError::timeout("rpc connect"))??;
        let json =
            serde_json::to_string(&request).map_err(|e| NetworkError::InvalidRpc(e.to_string()))?;
        write_message(&mut stream, &json).await?;
        let text = tokio::time::timeout(RPC_CLIENT_TIMEOUT, read_message(&mut stream))
            .await
            .map_err(|_| NetworkError::timeout("rpc response"))??;
        serde_json::from_str(&text)
            .map_err(|e| NetworkError::InvalidRpc(format!("bad response: {e}")))
    }
}

/// Binds the RPC listener (the config defaults to `127.0.0.1:0`).
///
/// # Errors
///
/// [`NetworkError::Io`] when the address cannot be bound.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr).await.map_err(NetworkError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn requests_roundtrip_through_json() {
        for request in [
            RpcRequest::Status,
            RpcRequest::SubmitTx {
                tx_hex: "00ff".into(),
            },
            RpcRequest::Lookup {
                name: "example.uip".into(),
            },
            RpcRequest::PutRecord {
                record_hex: "ab".into(),
            },
            RpcRequest::GetRecord {
                name: "example.uip".into(),
            },
        ] {
            let text = serde_json::to_string(&request).unwrap();
            assert_eq!(parse_request(&text).unwrap(), request);
        }
    }

    #[test]
    fn unknown_method_is_rejected() {
        assert!(parse_request(r#"{"method":"nope"}"#).is_err());
        assert!(parse_request("not json").is_err());
    }

    #[test]
    fn responses_serialize() {
        let ok = RpcResponse::ok(json!({"height": 3}));
        assert_eq!(
            serde_json::to_string(&ok).unwrap(),
            r#"{"status":"ok","data":{"height":3}}"#
        );
        let err = RpcResponse::error("boom");
        assert!(serde_json::to_string(&err).unwrap().contains("boom"));
    }

    #[tokio::test]
    async fn client_server_roundtrip() {
        let listener = bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Serve exactly the two connections of this test.
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                serve_connection(&mut stream, |req| async move {
                    match req {
                        RpcRequest::Status => RpcResponse::ok(json!({"height": 7})),
                        RpcRequest::Lookup { .. } => {
                            // Exercise the async dispatch path.
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            RpcResponse::ok(json!({"registered": false}))
                        }
                        other => RpcResponse::error(format!("unexpected {other:?}")),
                    }
                })
                .await
                .unwrap();
            }
        });
        let client = RpcClient::new(addr);
        let response = client.request(RpcRequest::Status).await.unwrap();
        assert_eq!(response.into_result().unwrap(), json!({"height": 7}));
        let response = client
            .request(RpcRequest::Lookup {
                name: "example.uip".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            response.into_result().unwrap(),
            json!({"registered": false})
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unreachable_relay_is_an_io_error() {
        // Bind then drop: the port is (almost certainly) closed.
        let listener = bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = RpcClient::new(addr);
        assert!(matches!(
            client.request(RpcRequest::Status).await,
            Err(NetworkError::Io(_))
        ));
    }
}
