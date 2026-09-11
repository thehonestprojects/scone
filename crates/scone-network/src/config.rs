//! Relay configuration.

use std::path::PathBuf;
use std::time::Duration;

use scone_core::{NetworkParams, TESTNET};

/// Default mempool capacity (transactions). The mempool is a strict
/// LRU-ish bounded structure: beyond this, new transactions are
/// rejected until blocks consume the queue.
pub const DEFAULT_MEMPOOL_CAPACITY: usize = 4096;

/// Default devnet block production interval.
pub const DEFAULT_PRODUCE_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum simultaneously parked DHT `get_record` waiters (audit M4,
/// M5): an RPC client can otherwise accumulate an unbounded number of
/// 30 s waiters. Above this cap, new lookups fail fast with
/// `LimitExceeded` instead of parking.
pub const MAX_DHT_WAITERS: usize = 256;

/// Maximum simultaneously served RPC connections (audit M4, M2): the
/// accept loop spawns one task per connection with no ceiling, a
/// local process could exhaust fds/memory by connection flooding.
/// Above this cap, new connections wait for a slot (bounded by the
/// RPC read timeout) instead of spawning freely.
pub const MAX_RPC_CONNECTIONS: usize = 64;

// Compile-time sanity: both caps finite and positive.
const _: () = assert!(MAX_DHT_WAITERS > 0);
const _: () = assert!(MAX_RPC_CONNECTIONS > 0);

/// Configuration of a relay.
#[derive(Debug, Clone)]
pub struct Config {
    /// Data directory (`chain.redb` lives here). The caller is
    /// responsible for giving each network its own directory (the
    /// CLI does: `~/.scone/testnet/`, `~/.scone/mainnet/`).
    pub data_dir: PathBuf,
    /// The network this relay belongs to (M8b): testnet by default
    /// while the project is in development; `mainnet` must be
    /// explicit. Drives the genesis, the PoW difficulties and the
    /// `WrongNetwork` rejection of foreign transactions.
    pub network: NetworkParams,
    /// P2P listen address (e.g. `/ip4/0.0.0.0/udp/0/quic-v1`).
    pub listen: Option<String>,
    /// Bootstrap multiaddrs dialed at startup.
    pub bootstrap: Vec<String>,
    /// Mempool capacity.
    pub mempool_capacity: usize,
    /// Devnet production interval.
    pub produce_interval: Duration,
    /// Local control RPC bind address.
    pub rpc_addr: std::net::SocketAddr,
    /// Optional UDP DNS server bind address (M6). `None` = no DNS
    /// surface. Defaults to OFF; binding 0.0.0.0:53 needs privileges.
    pub dns_addr: Option<std::net::SocketAddr>,
    /// Optional recursive DNS fallback upstreams (`addr:port`).
    /// Empty = Scone-unknown names get REFUSED.
    pub dns_upstreams: Vec<String>,
}

impl Config {
    /// Default configuration for `data_dir`.
    #[must_use]
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            network: TESTNET,
            listen: None,
            bootstrap: Vec::new(),
            mempool_capacity: DEFAULT_MEMPOOL_CAPACITY,
            produce_interval: DEFAULT_PRODUCE_INTERVAL,
            rpc_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            dns_addr: None,
            dns_upstreams: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let config = Config::new(PathBuf::from("/tmp/x"));
        assert_eq!(config.network, TESTNET);
        assert_eq!(config.mempool_capacity, DEFAULT_MEMPOOL_CAPACITY);
        assert_eq!(config.produce_interval, DEFAULT_PRODUCE_INTERVAL);
        assert_eq!(config.rpc_addr.port(), 0);
        assert!(config.bootstrap.is_empty());
    }
}
