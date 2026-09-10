//! Wire-format limits.
//!
//! Every length and count is checked against these constants **before**
//! any allocation, so a malicious peer can never force an absurd
//! allocation. The transport layer should additionally cap frames to
//! [`MAX_MESSAGE_LEN`].

/// Maximum encoded domain name length (matches `DomainName::MAX_TOTAL_LEN`).
pub const MAX_NAME_LEN: usize = scone_core::DomainName::MAX_TOTAL_LEN;

/// Maximum TXT string length.
pub const MAX_TXT_LEN: usize = 4096;

/// Maximum registration proof length (future proof-of-work output).
pub const MAX_PROOF_LEN: usize = 256;

/// Maximum signature length (Ed25519 is 64; headroom for scheme changes).
pub const MAX_SIGNATURE_LEN: usize = 128;

/// Maximum number of records in a record set.
pub const MAX_RECORDS_PER_SET: usize = 256;

/// Maximum data length of an unknown record type.
pub const MAX_UNKNOWN_DATA: usize = 4096;

/// Maximum number of transactions in a block.
pub const MAX_TXS_PER_BLOCK: usize = 4096;

/// Maximum consensus payload length in a block header.
pub const MAX_CONSENSUS_LEN: usize = 256;

/// Maximum number of blocks per `GetBlocks` request.
pub const MAX_BLOCKS_PER_REQUEST: usize = 128;

/// Recommended maximum message size for the (future) transport framing.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;
