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
    /// A `RegisterDomain` targets an already-registered domain.
    #[error("domain already registered")]
    DomainAlreadyRegistered,
    /// A `RegisterTld` targets an already-registered TLD.
    #[error("TLD already registered")]
    TldAlreadyRegistered,
    /// A `RegisterDomain` targets a TLD that is not registered: the
    /// namespace must be claimed first with a `RegisterTld` (D1, M7c
    /// — the chain is the authority over TLDs too). Also returned by
    /// `TransferTld`/`RevokeTld`/`SetTldOpen` on an unregistered TLD
    /// (M8b).
    #[error("unknown TLD")]
    UnknownTld,
    /// An `UpdateDomain` targets an unregistered domain. Also
    /// returned by `RenewDomain` (M8b).
    #[error("unknown domain")]
    UnknownDomain,
    /// An `UpdateDomain` is not signed by the current domain owner.
    #[error("transaction owner is not the domain owner")]
    NotOwner,
    /// An `UpdateDomain` sequence is not exactly `current + 1`.
    #[error("invalid sequence: expected {expected}, got {got}")]
    InvalidSequence {
        /// Sequence the transaction should carry.
        expected: u64,
        /// Sequence the transaction carries.
        got: u64,
    },
    /// A transaction of the M8a family (`TransferTld`, `RevokeTld`,
    /// `SetTldOpen`, `AssignDomain`, `RenewDomain`) reached a chain
    /// still running pre-M8b rules. Since M8b these variants have
    /// full state rules; the error remains for future, genuinely
    /// unknown variants.
    #[error("transaction type not yet applicable: {0}")]
    UnsupportedTransaction(&'static str),
    /// The transaction is built for another network: its
    /// `network` field does not match this chain's network id
    /// (M8b separation — a testnet tx never applies on mainnet and
    /// vice versa).
    #[error("wrong network: transaction targets {tx}, chain is {chain}")]
    WrongNetwork {
        /// Network the transaction is built for.
        tx: scone_core::NetworkId,
        /// Network of this chain.
        chain: scone_core::NetworkId,
    },
    /// A `RegisterDomain` targets a TLD closed for self-service
    /// registration: domains under it are created exclusively by the
    /// TLD owner with `AssignDomain` (M8b).
    #[error("TLD is closed for self-registration (assign-only)")]
    TldClosed,
    /// A TLD-owner operation (`TransferTld`, `RevokeTld`,
    /// `SetTldOpen`, `AssignDomain`) is not signed by the current
    /// TLD owner.
    #[error("transaction owner is not the TLD owner")]
    NotTldOwner,
    /// A `RenewDomain` would not extend the registration: the new
    /// expiry must be later than the current one (M8b).
    #[error("renewal does not extend the registration: current {current}, proposed {proposed}")]
    RenewalNotExtending {
        /// Current registration expiry (Unix seconds).
        current: u64,
        /// Proposed expiry (Unix seconds).
        proposed: u64,
    },
    /// A `RenewDomain` extends the registration by more than one
    /// renewal term beyond the current expiry (M8b anti-hoarding
    /// bound: 3 years per renewal, 3 years max ahead).
    #[error("renewal exceeds the maximum term: max {max}, proposed {proposed}")]
    RenewalExceedsTerm {
        /// Maximum allowed expiry (Unix seconds).
        max: u64,
        /// Proposed expiry (Unix seconds).
        proposed: u64,
    },
    /// A consensus hook rejected data (reason defined by the consensus
    /// implementation).
    #[error("consensus rejection: {0}")]
    Consensus(String),
    /// The `owner` field of a transaction is not the identity derived
    /// from its embedded `public_key` (recomputed — never trusted).
    #[error("transaction owner does not match its public key")]
    OwnerKeyMismatch,
    /// The signature of a transaction does not verify (strict Ed25519)
    /// over the recomputed canonical signing payload.
    #[error("invalid transaction signature")]
    InvalidSignature,
    /// A transaction violates a `scone-core` invariant, or its
    /// registration proof of work does not solve the network's
    /// difficulty (M8b).
    #[error("{0}")]
    Core(#[from] SconeError),
    /// The canonical encoding of a value failed (malformed header or
    /// transaction fields, e.g. oversized proof).
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// The signer guard (checkpoint crash safety) refused an operation:
    /// conflicting or past-epoch checkpoint, unreadable (sealed) signer
    /// state, or persistence failure — the signature was withheld and
    /// must not be broadcast.
    #[error("signer guard: {0}")]
    Signer(String),
}
