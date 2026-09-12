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
pub use redb::{
    MAX_DHT_CACHE_ENTRY, MAX_DOMAIN_PAGE, MAX_TLD_PAGE, NAME_INDEX_VERSION, RedbStore,
    SNAPSHOT_INTERVAL, name_index_key,
};
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

/// Metadata of the persisted canonical-state snapshot (M6b).
///
/// The snapshot freezes the FULL canonical state (domains + TLDs) as
/// of a block boundary strictly BELOW the tip (the writer only
/// snapshots when appending a new block, so the snapshot can never
/// sit at the tip). At boot, [`NodeStore::snapshot_meta`] plus the
/// snapshot tables let the chain restore this state and replay only
/// the blocks above it — O(tip − H) instead of a full replay.
///
/// `tip_hash` is the hash of the canonical block at `height`; the
/// boot path RECOMPUTES it from the stored block header and ignores
/// the snapshot on mismatch (fail-safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotMeta {
    /// Height of the snapshot state (its block's height).
    pub height: u64,
    /// Hash of the canonical block at `height` (recomputed at boot,
    /// never trusted).
    pub tip_hash: [u8; 32],
}

/// One page of domain states returned by [`NodeStore::iterate_domains`]:
/// up to `max` entries in ascending `DomainId` order, plus the cursor
/// (last id of the batch) for the next call. `None` cursor = start
/// from the beginning; after the final page the cursor equals the last
/// returned id.
pub type DomainPage = (Vec<(DomainId, DomainStateBytes)>, Option<DomainId>);

/// One P0.2 name-index binding carried in a [`StateDelta`].
///
/// `(is_tld, canonical name, target id bytes)`: the name→id mapping
/// is a pure function of the chain (the register/assign transactions
/// carry the canonical name), so the delta just re-states what the
/// block already proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameBinding {
    /// `true` = TLD namespace, `false` = domain namespace.
    pub is_tld: bool,
    /// Canonical name bound to `target`.
    pub name: String,
    /// The derived id (`DomainId`/`TldId` bytes — both 32).
    pub target: [u8; 32],
}

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
    /// Name-index upserts (P0.2): names bound by this block.
    pub name_upserts: Vec<NameBinding>,
    /// Name-index removals (P0.2): `(is_tld, id)` pairs unbound by
    /// this block (GC'd domains, revoked TLDs).
    pub name_removals: Vec<(bool, [u8; 32])>,
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

    /// Metadata of the persisted state snapshot, if any (M6b).
    ///
    /// Default: no snapshot (backends without snapshot support fall
    /// back to the plain state load — same guarantee as a pre-M6b
    /// store).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if the stored snapshot metadata
    /// does not decode; on I/O errors.
    fn snapshot_meta(&self) -> Result<Option<SnapshotMeta>> {
        Ok(None)
    }

    /// Reads up to `max` snapshot domain states with id strictly
    /// greater than `after`, in ascending `DomainId` order — same
    /// cursor contract as [`NodeStore::iterate_domains`], over the
    /// frozen snapshot tables (M6b).
    ///
    /// Default: empty (backend without snapshot support).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if any entry fails strict decoding.
    fn snapshot_domains(&self, after: Option<DomainId>, max: usize) -> Result<DomainPage> {
        let _ = (after, max);
        Ok((Vec::new(), None))
    }

    /// Reads up to `max` snapshot TLD states with id strictly greater
    /// than `after` — same cursor contract, over the frozen snapshot
    /// TLD registry (M6b). Default: empty.
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if any entry fails strict decoding.
    fn snapshot_tlds(&self, after: Option<TldId>, max: usize) -> Result<TldPage> {
        let _ = (after, max);
        Ok((Vec::new(), None))
    }

    /// Resolves a canonical domain name to its [`DomainId`] via the
    /// persistent name index (P0.2) — O(1) point lookup, no domain
    /// iteration. `canonical` MUST already be the canonical form
    /// (callers validate names with [`scone_core::DomainName`]).
    ///
    /// Default: `None` (backend without a name index — callers fall
    /// back to [`NodeStore::iterate_domains`] or the chain state).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if the stored index entry is
    /// malformed; on I/O errors.
    fn resolve_name(&self, canonical: &str) -> Result<Option<DomainId>> {
        let _ = canonical;
        Ok(None)
    }

    /// Resolves a canonical TLD name to its [`TldId`] via the
    /// persistent name index (P0.2) — TLD variant of
    /// [`NodeStore::resolve_name`].
    ///
    /// Default: `None`.
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if the stored index entry is
    /// malformed; on I/O errors.
    fn resolve_tld(&self, tld: &str) -> Result<Option<TldId>> {
        let _ = tld;
        Ok(None)
    }
}
