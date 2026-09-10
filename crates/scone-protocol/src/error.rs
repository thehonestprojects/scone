//! Errors of the protocol codec.

use scone_core::SconeError;
use thiserror::Error;

/// Result alias for the protocol crate.
pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Encoding/decoding errors.
///
/// Every malformed input (truncated, non-canonical, over limit, unknown
/// discriminant or version) maps to one of these variants; decoding never
/// panics on network data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// Input ended in the middle of a value.
    #[error("unexpected end of input")]
    Truncated,
    /// A varint is malformed (non-minimal, overflowing or too long).
    #[error("invalid varint: {0}")]
    InvalidVarint(&'static str),
    /// A decoded integer does not fit its target type.
    #[error("integer out of range: {0}")]
    IntegerOutOfRange(&'static str),
    /// A version newer than [`crate::PROTOCOL_VERSION`] (or zero) was
    /// received.
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u64),
    /// An unknown type discriminator was received.
    #[error("unknown {kind} discriminant: {value:#04x}")]
    UnknownDiscriminant { kind: &'static str, value: u8 },
    /// A length or count exceeds its protocol limit (see [`crate::limits`]).
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    /// A string payload is not valid UTF-8.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// An embedded Ed25519 public key does not decode to a valid curve
    /// point.
    #[error("invalid transaction public key")]
    InvalidTransactionKey,
    /// Extra bytes remain after a complete value was decoded.
    #[error("{0} trailing bytes after value")]
    TrailingBytes(usize),
    /// The value violates a core invariant (re-validated on decode).
    #[error(transparent)]
    Validation(#[from] SconeError),
    /// The encoding is field-valid but not canonical (e.g. unsorted record
    /// set).
    #[error("non-canonical encoding: {0}")]
    NonCanonical(&'static str),
}
