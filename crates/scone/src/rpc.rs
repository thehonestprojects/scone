//! Relay RPC client helpers (fresh tokio runtime per round
//! trip, JSON rendering) and the thin RPC commands
//! `scone status`, `scone submit tx` and `scone lookup`.

use tracing::debug;

use crate::cli::SubmitCommand;
use crate::error::CliError;

/// Default relay RPC address.
pub(crate) const DEFAULT_RPC_ADDR: &str = "127.0.0.1:7474";

/// Builds an RPC client for the given `--rpc` value (or the default).
pub(crate) fn rpc_client(rpc: Option<&str>) -> Result<scone_network::RpcClient, CliError> {
    let text = rpc.unwrap_or(DEFAULT_RPC_ADDR);
    let addr: std::net::SocketAddr = text
        .parse()
        .map_err(|_| CliError::InvalidRpcAddr(text.to_string()))?;
    Ok(scone_network::RpcClient::new(addr))
}

/// Runs one async RPC round trip on a fresh tokio runtime (the CLI
/// stays synchronous everywhere else).
pub(crate) fn rpc_call(
    client: &scone_network::RpcClient,
    request: scone_network::RpcRequest,
) -> Result<Vec<String>, CliError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    debug!(addr = %client.addr(), "rpc round trip");
    let response = rt.block_on(client.request(request)).map_err(|e| match e {
        scone_network::NetworkError::Io(_) | scone_network::NetworkError::Timeout(_) => {
            CliError::RelayUnreachable(client_addr(client))
        }
        other => CliError::RelayError(other.to_string()),
    })?;
    match response {
        scone_network::RpcResponse::Ok { data } => Ok(render_json(&data)),
        scone_network::RpcResponse::Error { message } => Err(CliError::RelayError(message)),
    }
}

/// The client's address as a display string.
fn client_addr(client: &scone_network::RpcClient) -> String {
    client.addr().to_string()
}

/// Renders a JSON value as aligned `key: value` lines (objects) or a
/// single line otherwise.
fn render_json(value: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}: {}", render_flat(v)))
            .collect(),
        other => vec![render_flat(other)],
    }
}

/// Renders a JSON scalar/array as one flat string.
fn render_flat(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Runs `scone status`.
pub(crate) fn run_status(rpc: Option<String>) -> Result<Vec<String>, CliError> {
    let client = rpc_client(rpc.as_deref())?;
    rpc_call(&client, scone_network::RpcRequest::Status)
}

/// Runs `scone submit tx …`.
pub(crate) fn run_submit(command: SubmitCommand) -> Result<Vec<String>, CliError> {
    let SubmitCommand::Tx { hex, rpc } = command;
    let client = rpc_client(rpc.as_deref())?;
    rpc_call(
        &client,
        scone_network::RpcRequest::SubmitTx {
            tx_hex: hex.to_lowercase(),
        },
    )
}

/// Runs `scone lookup <name>`.
pub(crate) fn run_lookup(name: String, rpc: Option<String>) -> Result<Vec<String>, CliError> {
    let client = rpc_client(rpc.as_deref())?;
    rpc_call(&client, scone_network::RpcRequest::Lookup { name })
}

/// Runs one async RPC round trip and returns the raw `data` value.
pub(crate) fn rpc_json(
    client: &scone_network::RpcClient,
    request: scone_network::RpcRequest,
) -> Result<serde_json::Value, CliError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    let response = rt.block_on(client.request(request)).map_err(|e| match e {
        scone_network::NetworkError::Io(_) | scone_network::NetworkError::Timeout(_) => {
            CliError::RelayUnreachable(client_addr(client))
        }
        other => CliError::RelayError(other.to_string()),
    })?;
    match response {
        scone_network::RpcResponse::Ok { data } => Ok(data),
        scone_network::RpcResponse::Error { message } => Err(CliError::RelayError(message)),
    }
}
