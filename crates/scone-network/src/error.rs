//! Typed errors of the network layer.

use thiserror::Error;

/// Result alias of the crate.
pub type Result<T> = std::result::Result<T, NetworkError>;

/// Errors of the relay, its RPC and its protocols.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// A frame/record/message exceeded its size bound before any
    /// parsing or allocation.
    #[error("size limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A peer (or the local RPC client) sent bytes that failed strict
    /// protocol decoding.
    #[error("protocol error: {0}")]
    Protocol(#[from] scone_protocol::ProtocolError),
    /// The chain rejected a block or transaction (full validation).
    #[error("blockchain error: {0}")]
    Blockchain(#[from] scone_blockchain::BlockchainError),
    /// The local persistent store failed.
    #[error("storage error: {0}")]
    Storage(#[from] scone_storage::StorageError),
    /// A keystore operation failed.
    #[error("keystore error: {0}")]
    Keystore(#[from] scone_keystore::Error),
    /// The P2P swarm raised an I/O or transport error.
    #[error("libp2p i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A pending network operation timed out.
    #[error("timeout: {0}")]
    Timeout(String),
    /// A peer misbehaved (bad handshake, unsolicited response…).
    #[error("peer error: {0}")]
    Peer(String),
    /// The swarm was asked for an unknown pending request.
    #[error("unknown pending request")]
    UnknownRequest,
    /// Invalid RPC request (bad JSON, bad hex, unknown method).
    #[error("invalid rpc request: {0}")]
    InvalidRpc(String),
    /// The chain does not know the requested domain.
    #[error("unknown domain")]
    UnknownDomain,
    /// A record failed verification against the chain state.
    #[error("record rejected: {0}")]
    RecordRejected(String),
    /// The record could not be found in the DHT.
    #[error("record not found")]
    RecordNotFound,
    /// DHT store/fetch failure.
    #[error("dht error: {0}")]
    Dht(String),
}

impl NetworkError {
    /// Builds a [`NetworkError::Timeout`] (small helper to avoid
    /// stringly building at every call site).
    #[must_use]
    pub fn timeout(context: &str) -> Self {
        Self::Timeout(context.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_helper_builds_the_right_variant() {
        assert_eq!(
            NetworkError::timeout("sync").to_string(),
            "timeout: sync".to_string()
        );
    }
}
