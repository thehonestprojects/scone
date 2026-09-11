//! # scone-storage
//!
//! Persistent local storage for Scone nodes (embedded `redb` backend).
//!
//! This crate defines the [`NodeStore`] trait — the only storage surface
//! the blockchain and the future relay (M4) depend on — plus
//! [`DomainStateBytes`] and [`TldStateBytes`], the storage-level
//! encodings of a [`scone_blockchain::DomainState`] and of a
//! [`scone_blockchain::TldState`] (the [`scone-blockchain`] types stay
//! in RAM; only fixed-size bytes cross the trait boundary — 41/73 for
//! domains depending on the presence of a `record_hash`, 33 for TLDs).
//!
//! ## Design rules (see `/docs/technical/storage.md`)
//!
//! - **No redb types in the API**: the trait speaks bytes and core types
//!   only, so the backend can be swapped (tests use redb tmpfiles).
//! - **Async-free, no interior mutability**: writes take `&mut self`,
//!   redb serializes them; reads take `&self` and open short-lived redb
//!   read transactions per call.
//! - **Batched reads only**: [`NodeStore::iterate_domains`] pages
//!   through the domains table with a lazy cursor (default 100 per
//!   batch). Nothing in this crate ever loads a whole table into RAM.
//! - **Delta-only writes**: [`NodeStore::append_block_with_state`]
//!   persists only the block bytes, the tip, and the *modified*
//!   domain and TLD states, all in ONE redb transaction.
//! - **Never panics on corrupted data**: every stored byte is decoded
//!   strictly into typed [`StorageError`]s.

pub mod error;
pub mod integration;
pub mod redb;
pub mod state_bytes;

pub use error::{Result, StorageError};
pub use redb::{MAX_DHT_CACHE_ENTRY, MAX_DOMAIN_PAGE, MAX_TLD_PAGE, RedbStore};
pub use state_bytes::{DomainStateBytes, TldStateBytes};

use scone_core::{DomainId, TldId};

/// Storage format version written to the `meta` table at creation
/// (`meta["format_version"]`). Bump and migrate when the on-disk layout
/// changes.
pub const STORAGE_FORMAT_VERSION: u64 = 1;

/// Key of the canonical tip hash (`BlockHash` bytes) in the `meta`
/// table. The tip height is derivable from
/// `blocks_by_hash[tip]["height"]`.
pub const META_TIP: &[u8] = b"tip";

/// Key of the storage format version in the `meta` table.
pub const META_FORMAT_VERSION: &[u8] = b"format_version";

/// One page of domain states returned by [`NodeStore::iterate_domains`]:
/// up to `max` entries in ascending `DomainId` order, plus the cursor
/// (last id of the batch) for the next call. `None` cursor = start
/// from the beginning; after the final page the cursor equals the last
/// returned id.
pub type DomainPage = (Vec<(DomainId, DomainStateBytes)>, Option<DomainId>);

/// The state changes of one block (M8b): upserts and removals for
/// both registries, applied atomically with the block bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateDelta {
    /// Domain states to write (last write wins per id).
    pub domains: Vec<(DomainId, DomainStateBytes)>,
    /// TLD states to write.
    pub tlds: Vec<(TldId, TldStateBytes)>,
    /// Domain states to delete (M8b GC of expired registrations).
    pub removed_domains: Vec<DomainId>,
    /// TLD states to delete (M8b RevokeTld).
    pub removed_tlds: Vec<TldId>,
}

impl StateDelta {
    /// An empty delta (block with no state change).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// One page of TLD states returned by [`NodeStore::iterate_tlds`]:
/// same cursor contract as [`DomainPage`], over `TldId`s (M7d).
pub type TldPage = (Vec<(TldId, TldStateBytes)>, Option<TldId>);

/// Persistent node storage front-end (blocks, domain states, DHT cache,
/// metadata).
///
/// Implementations MUST provide:
///
/// - **atomic block appends**: [`NodeStore::append_block`] and
///   [`NodeStore::append_block_with_state`] either persist everything
///   (block bytes, both indexes, tip, domain deltas, counters) or
///   nothing — a stored block without its state updates is forbidden
///   (crash safety);
/// - **strict decoding**: malformed stored values produce
///   [`StorageError::Corrupted`]-style errors, never panics;
/// - **cheap reads**: point lookups open a single read transaction;
///   bulk reads go through [`NodeStore::iterate_domains`] (cursor).
pub trait NodeStore {
    /// Appends an encoded block as the new canonical tip.
    ///
    /// `height` MUST be `parent height + 1` and `hash` the recomputed
    /// block hash (the store does not re-validate blocks — that is
    /// `scone-blockchain`'s job).
    ///
    /// # Errors
    ///
    /// [`StorageError::NonMonotonicHeight`] if `height` is not exactly
    /// `tip height + 1`; other variants on I/O or encoding failures.
    fn append_block(&mut self, height: u64, hash: &[u8; 32], block_bytes: &[u8]) -> Result<()>;

    /// Atomic **delta** append: encoded block + tip + the modified
    /// domain and TLD states, in ONE transaction.
    ///
    /// Only the domains listed in `state_deltas` and the TLDs listed
    /// in `tld_deltas` are rewritten (the chain state in RAM stays
    /// the consensus authority; the store never re-persists
    /// unmodified entries). `height` MUST be `tip height + 1`.
    ///
    /// # Errors
    ///
    /// See [`NodeStore::append_block`].
    fn append_block_with_state(
        &mut self,
        height: u64,
        hash: &[u8; 32],
        block_bytes: &[u8],
        deltas: &StateDelta,
    ) -> Result<()>;

    /// Encoded canonical block at `height`, if stored.
    ///
    /// # Errors
    ///
    /// On I/O errors or a stored block larger than [`usize::MAX`].
    fn block_at_height(&self, height: u64) -> Result<Option<Vec<u8>>>;

    /// Encoded canonical block with hash `hash`, if stored.
    ///
    /// # Errors
    ///
    /// On I/O errors or a stored block larger than [`usize::MAX`].
    fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>>;

    /// Current canonical tip: `(height, hash)`. Genesis when the store
    /// is empty (height 0 — genesis is not stored as block bytes, it is
    /// deterministic).
    ///
    /// # Errors
    ///
    /// On I/O errors or corrupted metadata.
    fn tip(&self) -> Result<(u64, [u8; 32])>;

    /// Persists the state of one domain ( RegisterDomain/UpdateDomain replay,
    /// repair tools). Prefer [`NodeStore::append_block_with_state`] on
    /// the block path.
    ///
    /// # Errors
    ///
    /// On I/O errors.
    fn put_domain_state(&mut self, domain: DomainId, state: DomainStateBytes) -> Result<()>;

    /// Stored state of `domain`, if any.
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if the stored bytes are not a valid
    /// `DomainStateBytes`.
    fn domain_state(&self, domain: &DomainId) -> Result<Option<DomainStateBytes>>;

    /// Number of stored domain states, from a maintained counter (never
    /// a full-table scan).
    ///
    /// # Errors
    ///
    /// On I/O errors or corrupted metadata.
    fn domain_count(&self) -> Result<u64>;

    /// Reads up to `max` domain states with id strictly greater than
    /// `after`, in ascending `DomainId` byte order, returning the last
    /// id of the batch (the cursor for the next call).
    ///
    /// Pass `None`/`0` to start from the beginning. This is the ONLY
    /// sanctioned way to walk the domains table: it pages through a
    /// lazy redb range cursor and never materializes the table.
    /// Implementations bound the page: a `max` above
    /// [`MAX_DOMAIN_PAGE`] is clamped to it (DoS guard).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if any entry fails strict decoding.
    fn iterate_domains(&self, after: Option<DomainId>, max: usize) -> Result<DomainPage>;

    /// Persists the state of one TLD (repair tools; the block path
    /// goes through [`NodeStore::append_block_with_state`]'s
    /// `tld_deltas`) (M7d).
    ///
    /// # Errors
    ///
    /// On I/O errors.
    fn put_tld_state(&mut self, tld: TldId, state: TldStateBytes) -> Result<()>;

    /// Stored state of `tld`, if any (M7d).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if the stored bytes are not a valid
    /// `TldStateBytes`.
    fn tld_state(&self, tld: &TldId) -> Result<Option<TldStateBytes>>;

    /// Number of stored TLD states, from a maintained counter (never
    /// a full-table scan) (M7d).
    ///
    /// # Errors
    ///
    /// On I/O errors or corrupted metadata.
    fn tld_count(&self) -> Result<u64>;

    /// Reads up to `max` TLD states with id strictly greater than
    /// `after`, in ascending `TldId` byte order, returning the last
    /// id of the batch — same cursor contract as
    /// [`NodeStore::iterate_domains`], bounded by
    /// [`MAX_TLD_PAGE`] (M7d).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if any entry fails strict decoding.
    fn iterate_tlds(&self, after: Option<TldId>, max: usize) -> Result<TldPage>;

    /// Caches the encoded `SignedDnsRecord` of `domain` (DHT
    /// availability layer — untrusted until verified against the
    /// chain).
    ///
    /// # Errors
    ///
    /// [`StorageError::TooLarge`] if `record_bytes` exceeds
    /// [`MAX_DHT_CACHE_ENTRY`] (DoS guard — checked before any write);
    /// on I/O errors.
    fn put_dht_cache(&mut self, domain: DomainId, record_bytes: &[u8]) -> Result<()>;

    /// Cached encoded `SignedDnsRecord` of `domain`, if any.
    ///
    /// # Errors
    ///
    /// On I/O errors.
    fn dht_cache(&self, domain: &DomainId) -> Result<Option<Vec<u8>>>;

    /// Arbitrary metadata value (tip bookkeeping, versions).
    ///
    /// # Errors
    ///
    /// On I/O errors.
    fn meta_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Sets a metadata value. Keys reserved for the store's internal
    /// bookkeeping (`tip`, `tip_height`, `format_version`,
    /// `domain_count`) are rejected — clobbering them would corrupt
    /// the store.
    ///
    /// # Errors
    ///
    /// [`StorageError::ReservedKey`] on a reserved key; on I/O errors.
    fn meta_set(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
}
