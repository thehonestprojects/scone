//! Central error type for the core.

use thiserror::Error;

/// Result alias for the core.
pub type Result<T> = std::result::Result<T, SconeError>;

/// Errors of the Scone core.
///
/// Pure, local validation errors only. Network, storage (redb) and OS
/// errors belong to their own crates and must be translated into
/// [`SconeError`] at their boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SconeError {
    /// A generic name is syntactically invalid.
    #[error("invalid name: {0}")]
    InvalidName(String),

    /// The TLD does not match `[a-z0-9]{{1,5}}`.
    #[error("invalid TLD: {0}")]
    InvalidTld(String),

    /// The domain name violates the naming rules (see `/docs/naming.md`).
    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    /// A DNS record violates protocol invariants.
    #[error("invalid record: {0}")]
    InvalidRecord(String),

    /// A transaction violates protocol invariants.
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// An owner identity is malformed.
    #[error("invalid owner: {0}")]
    InvalidOwner(String),

    /// A sequence number is zero.
    #[error("invalid sequence: {0}")]
    InvalidSequence(u64),

    /// Generic malformed data (decoding, encoding, framing).
    #[error("invalid format: {0}")]
    InvalidFormat(String),
}
