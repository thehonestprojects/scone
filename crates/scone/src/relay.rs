//! `scone relay …`: runs the foreground relay daemon.

use std::path::PathBuf;

use tracing::info;

use crate::error::CliError;
use crate::rpc::DEFAULT_RPC_ADDR;

/// Runs `scone relay …` (foreground daemon).
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_relay(
    data_dir: Option<PathBuf>,
    listen: Option<String>,
    bootstrap: Vec<String>,
    rpc: Option<String>,
    dns: Option<String>,
    dns_upstream: Vec<String>,
) -> Result<Vec<String>, CliError> {
    let data_dir = data_dir.unwrap_or_else(|| match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".scone"),
        None => PathBuf::from(".scone"),
    });
    let mut config = scone_network::Config::new(data_dir);
    if let Some(listen) = listen {
        config.listen = Some(listen);
    }
    config.bootstrap = bootstrap;
    // Devnet defaults: fixed RPC port so the CLI can find us, unless
    // --rpc says otherwise (two relays on one machine).
    let rpc_text = rpc.as_deref().unwrap_or(DEFAULT_RPC_ADDR);
    config.rpc_addr = rpc_text
        .parse()
        .map_err(|_| CliError::InvalidRpcAddr(rpc_text.to_string()))?;
    // M6: optional UDP DNS surface + optional fallback upstreams.
    if let Some(dns_text) = dns.as_deref() {
        config.dns_addr = Some(
            dns_text
                .parse()
                .map_err(|_| CliError::InvalidRpcAddr(dns_text.to_string()))?,
        );
    }
    config.dns_upstreams = dns_upstream;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    rt.block_on(async move {
        let relay =
            scone_network::Relay::new(config).map_err(|e| CliError::RelayError(e.to_string()))?;
        info!(peer = %relay.peer_id(), "starting relay");
        relay
            .run()
            .await
            .map_err(|e| CliError::RelayError(e.to_string()))
    })?;
    Ok(Vec::new())
}
