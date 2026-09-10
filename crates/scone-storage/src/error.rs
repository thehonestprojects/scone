//! Errors of the storage layer.

use thiserror::Error;

/// Result alias for the storage crate.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Errors raised by persistent storage operations.
///
/// Corrupted or hostile on-disk data maps to typed variants; nothing
/// ever panics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StorageError {
    /// A block was appended at a height that is not exactly
    /// `tip height + 1`.
    #[error("non-monotonic height: expected {expected}, got {got}")]
    NonMonotonicHeight {
        /// Height the block should have.
        expected: u64,
        /// Height the block announces.
        got: u64,
    },
    /// An id is already bound to different content (e.g. a height
    /// already holds another block).
    #[error("conflict on {what}: {id}")]
    Conflict {
        /// What conflicts (table/logical name).
        what: &'static str,
        /// Offending identifier (hex).
        id: String,
    },
    /// A value exceeds a storage-layer size bound (DoS guard: a
    /// hostile peer must not be able to make the node persist
    /// unbounded blobs).
    #[error("entry too large: {len} bytes (max {max})")]
    TooLarge {
        /// Actual size of the rejected value.
        len: usize,
        /// Maximum allowed size.
        max: usize,
    },
    /// A `meta` key reserved for the store's internal bookkeeping
    /// (`tip`, `tip_height`, `format_version`, `domain_count`).
    #[error("reserved meta key: {0}")]
    ReservedKey(String),
    /// Stored bytes do not decode as the expected type.
    #[error("corrupted storage: {0}")]
    Corrupted(String),
    /// The stored state was written by an incompatible storage format.
    #[error("unsupported storage format version: {0}")]
    UnsupportedFormat(u64),
    /// The database file could not be opened or is corrupted.
    #[error("database error: {0}")]
    Database(String),
    /// A read/write transaction failed.
    #[error("transaction error: {0}")]
    Transaction(String),
    /// A table operation failed.
    #[error("table error: {0}")]
    Table(String),
    /// A transaction commit failed (nothing was persisted).
    #[error("commit error: {0}")]
    Commit(String),
    /// A redb error not mapped to a more precise variant.
    #[error("storage backend error: {0}")]
    Backend(String),
}

impl From<redb::Error> for StorageError {
    fn from(err: redb::Error) -> Self {
        Self::Backend(err.to_string())
    }
}

impl From<redb::DatabaseError> for StorageError {
    fn from(err: redb::DatabaseError) -> Self {
        Self::Database(err.to_string())
    }
}

impl From<redb::TransactionError> for StorageError {
    fn from(err: redb::TransactionError) -> Self {
        Self::Transaction(err.to_string())
    }
}

impl From<redb::TableError> for StorageError {
    fn from(err: redb::TableError) -> Self {
        Self::Table(err.to_string())
    }
}

impl From<redb::CommitError> for StorageError {
    fn from(err: redb::CommitError) -> Self {
        Self::Commit(err.to_string())
    }
}

impl From<redb::StorageError> for StorageError {
    fn from(err: redb::StorageError) -> Self {
        Self::Backend(err.to_string())
    }
}
