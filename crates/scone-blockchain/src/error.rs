//! Errors of the blockchain layer.

use scone_core::SconeError;
use scone_protocol::ProtocolError;
use thiserror::Error;

/// Result alias for the blockchain crate.
pub type Result<T> = std::result::Result<T, BlockchainError>;

/// Errors raised while validating or applying blockchain data.
///
/// Every malformed or hostile input (peer-provided block, transaction,
/// state operation) maps to one of these variants; nothing ever panics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlockchainError {
    /// The parent hash references a block this chain has never seen.
    #[error("unknown parent block")]
    UnknownParent,
    /// The parent hash references a known block that is not the
    /// canonical tip: a fork this implementation refuses to follow
    /// (fork choice belongs to the future consensus).
    #[error("parent is not the canonical tip (fork)")]
    ParentNotTip,
    /// Block height is not exactly `parent height + 1`.
    #[error("invalid height: expected {expected}, got {got}")]
    InvalidHeight {
        /// Height the block should have.
        expected: u64,
        /// Height the block announces.
        got: u64,
    },
    /// Block version is zero or above the local protocol version.
    #[error("invalid block version: {0}")]
    InvalidVersion(u32),
    /// The recomputed Merkle root does not match `BlockHeader::tx_root`.
    #[error("merkle root mismatch")]
    MerkleMismatch,
    /// More transactions than `MAX_TXS_PER_BLOCK`.
    #[error("too many transactions: {0}")]
    TooManyTransactions(usize),
    /// A `Register` targets an already-registered domain.
    #[error("domain already registered")]
    DomainAlreadyRegistered,
    /// An `Update` targets an unregistered domain.
    #[error("unknown domain")]
    UnknownDomain,
    /// An `Update` is not signed by the current domain owner.
    #[error("transaction owner is not the domain owner")]
    NotOwner,
    /// An `Update` sequence is not exactly `current + 1`.
    #[error("invalid sequence: expected {expected}, got {got}")]
    InvalidSequence {
        /// Sequence the transaction should carry.
        expected: u64,
        /// Sequence the transaction carries.
        got: u64,
    },
    /// A consensus hook rejected data (reason defined by the consensus
    /// implementation).
    #[error("consensus rejection: {0}")]
    Consensus(String),
    /// A transaction violates a `scone-core` invariant.
    #[error(transparent)]
    Core(#[from] SconeError),
    /// The canonical encoding of a value failed (malformed header or
    /// transaction fields, e.g. oversized proof).
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}
