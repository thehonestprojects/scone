//! `redb` backend of [`NodeStore`](crate::NodeStore).
//!
//! ## Tables
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `blocks_by_height` | `u64` height (ordered) | block hash `32` + height `8 BE` + canonical block bytes |
//! | `blocks_by_hash` | block hash (`32`) | canonical block bytes |
//! | `domains` | `DomainId` (`32`, ordered) | [`DomainStateBytes`] |
//! | `dht_cache` | `DomainId` (`32`) | encoded `SignedDnsRecord` |
//! | `meta` | `&[u8]` | `&[u8]` (tip, tip height, format version, domain counter) |
//!
//! ## Guarantees
//!
//! - **ACID appends**: [`RedbStore::append_block_with_state`] writes
//!   the block in both indexes, the tip, the domain deltas and the
//!   domain counter in a single `WriteTransaction` — a crash mid-write
//!   leaves the previous consistent state (WAL-style commit). A block
//!   stored without its state updates is impossible by construction.
//! - **Snapshot reads**: each read opens a short redb read transaction;
//!   readers never block the writer.
//! - **Lazy cursors**: `iterate_domains` walks a `range` cursor and
//!   stops after `max` entries; no table is ever fully materialized.
//! - **Strict decoding**: any malformed stored value becomes a typed
//!   [`StorageError`], never a panic.
//!
//! ## Genesis convention
//!
//! The genesis block is deterministic and never stored as bytes. A fresh
//! store has `tip == (0, genesis_hash)`; the first appended block has
//! height 1.

use std::path::Path;
use std::sync::Arc;

use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use scone_core::DomainId;

use crate::error::{Result, StorageError};
use crate::state_bytes::decode_domain_entry;
use crate::{DomainStateBytes, META_FORMAT_VERSION, META_TIP, NodeStore, STORAGE_FORMAT_VERSION};

/// `height -> hash(32) || height(8 BE) || block bytes`.
type BlocksByHeight = TableDefinition<'static, u64, &'static [u8]>;
/// `block_hash(32) -> block bytes`.
type BlocksByHash = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `DomainId(32) -> DomainStateBytes`.
type Domains = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `DomainId(32) -> encoded SignedDnsRecord`.
type DhtCache = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `meta key -> meta value`.
type Meta = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// `meta` key of the cached tip height (keeps `tip()` O(1)).
const META_TIP_HEIGHT: &[u8] = b"tip_height";
/// `meta` key of the maintained domain-state counter (never `COUNT(*)`).
const META_DOMAIN_COUNT: &[u8] = b"domain_count";

/// Maximum size of one cached DHT record (DoS guard): a hostile peer
/// must not be able to make the node persist unbounded blobs.
pub const MAX_DHT_CACHE_ENTRY: usize = 64 * 1024;

/// Internal cap on a single `iterate_domains` page (DoS guard): the
/// caller's `max` is clamped to this bound, so a bogus huge `max`
/// still yields a memory-bounded page.
pub const MAX_DOMAIN_PAGE: usize = 10_000;

/// Rejects `meta` keys reserved for the store's internal
/// bookkeeping — clobbering them would silently corrupt the store.
fn ensure_not_reserved(key: &[u8]) -> Result<()> {
    if key == META_TIP
        || key == META_TIP_HEIGHT
        || key == META_FORMAT_VERSION
        || key == META_DOMAIN_COUNT
    {
        return Err(StorageError::ReservedKey(
            String::from_utf8_lossy(key).into_owned(),
        ));
    }
    Ok(())
}

/// Header prefix of a `blocks_by_height` value: hash + height.
const BLOCK_INDEX_HEADER: usize = 32 + 8;

const BLOCKS_BY_HEIGHT: BlocksByHeight = TableDefinition::new("blocks_by_height");
const BLOCKS_BY_HASH: BlocksByHash = TableDefinition::new("blocks_by_hash");
const DOMAINS: Domains = TableDefinition::new("domains");
const DHT_CACHE: DhtCache = TableDefinition::new("dht_cache");
const META: Meta = TableDefinition::new("meta");

/// `redb`-backed [`NodeStore`].
///
/// The inner `redb::Database` is wrapped in an [`Arc`] so several
/// handles (threads) can read concurrently; write access requires
/// `&mut self`, which redb complements with internal write
/// serialization.
#[derive(Debug, Clone)]
pub struct RedbStore {
    db: Arc<redb::Database>,
}

/// Genesis hash (32 bytes) — re-derived, never stored, never trusted.
fn genesis_hash_bytes() -> [u8; 32] {
    *scone_blockchain::genesis_hash().as_bytes()
}

/// Reads a strictly 8-byte big-endian u64 from `meta`, `what` naming
/// the key for error messages.
fn meta_u64<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    key: &[u8],
    what: &str,
) -> Result<u64> {
    let bytes = table
        .get(key)?
        .map(|g| g.value().as_ref().to_vec())
        .ok_or_else(|| StorageError::Corrupted(format!("meta {what}: missing")))?;
    if bytes.len() != 8 {
        return Err(StorageError::Corrupted(format!("meta {what}: not 8 bytes")));
    }
    Ok(u64::from_be_bytes(bytes.try_into().expect("len checked")))
}

/// Reads a strictly 32-byte value from `meta`, `what` naming the key.
fn meta_u256<T: ReadableTable<&'static [u8], &'static [u8]>>(
    table: &T,
    key: &[u8],
    what: &str,
) -> Result<[u8; 32]> {
    let bytes = table
        .get(key)?
        .map(|g| g.value().as_ref().to_vec())
        .ok_or_else(|| StorageError::Corrupted(format!("meta {what}: missing")))?;
    bytes
        .try_into()
        .map_err(|_| StorageError::Corrupted(format!("meta {what}: not 32 bytes")))
}

/// Writes `tip` + `tip_height` inside an open write transaction.
fn write_tip(
    meta: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    height: u64,
    hash: &[u8; 32],
) -> Result<()> {
    meta.insert(META_TIP, &hash[..])?;
    meta.insert(META_TIP_HEIGHT, &height.to_be_bytes()[..])?;
    Ok(())
}

impl RedbStore {
    /// Opens (or creates) the store at `path`, creating the tables and
    /// seeding `meta` (`format_version`, `tip` = genesis, counters) in
    /// one transaction.
    ///
    /// # Errors
    ///
    /// [`StorageError::Database`] if the file cannot be opened or is
    /// corrupted; [`StorageError::UnsupportedFormat`] on an unknown
    /// format version; [`StorageError::Corrupted`] on inconsistent
    /// metadata.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = redb::Database::create(path)?;
        let store = Self { db: Arc::new(db) };
        let wtxn = store.db.begin_write()?;
        {
            let _ = wtxn.open_table(BLOCKS_BY_HEIGHT)?;
            let _ = wtxn.open_table(BLOCKS_BY_HASH)?;
            let _ = wtxn.open_table(DOMAINS)?;
            let _ = wtxn.open_table(DHT_CACHE)?;
            let mut meta_t = wtxn.open_table(META)?;
            if meta_t.get(META_FORMAT_VERSION)?.is_none() {
                meta_t.insert(
                    META_FORMAT_VERSION,
                    &STORAGE_FORMAT_VERSION.to_be_bytes()[..],
                )?;
                write_tip(&mut meta_t, 0, &genesis_hash_bytes())?;
                meta_t.insert(META_DOMAIN_COUNT, &0u64.to_be_bytes()[..])?;
            }
        }
        wtxn.commit()?;
        store.check_format_version()?;
        Ok(store)
    }

    /// Fails with [`StorageError::UnsupportedFormat`] if the on-disk
    /// format version is not the one this build understands.
    fn check_format_version(&self) -> Result<()> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(META)?;
        let bytes = table
            .get(META_FORMAT_VERSION)?
            .map(|g| g.value().as_ref().to_vec())
            .ok_or_else(|| StorageError::Corrupted("meta format_version: missing".into()))?;
        if bytes.len() != 8 {
            return Err(StorageError::Corrupted(
                "meta format_version: not 8 bytes".into(),
            ));
        }
        let version = u64::from_be_bytes(bytes.try_into().expect("len checked"));
        if version != STORAGE_FORMAT_VERSION {
            return Err(StorageError::UnsupportedFormat(version));
        }
        Ok(())
    }

    /// `(height, hash)` of the canonical tip from `meta` (single read
    /// transaction, no block scan).
    fn tip_inner(&self) -> Result<(u64, [u8; 32])> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(META)?;
        let hash = meta_u256(&table, META_TIP, "tip")?;
        let height = meta_u64(&table, META_TIP_HEIGHT, "tip_height")?;
        Ok((height, hash))
    }

    /// Maintained domain-state counter (never a table scan).
    fn domain_count_inner(&self) -> Result<u64> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(META)?;
        meta_u64(&table, META_DOMAIN_COUNT, "domain_count")
    }
}

/// Shared core of both append entry points: everything below runs in
/// the caller's single write transaction (ACID unit).
fn append_core(
    wtxn: &mut redb::WriteTransaction,
    height: u64,
    hash: &[u8; 32],
    block_bytes: &[u8],
    state_deltas: &[(DomainId, DomainStateBytes)],
) -> Result<()> {
    // Pre-encoded value for blocks_by_height: hash || height || bytes.
    let mut indexed = Vec::with_capacity(BLOCK_INDEX_HEADER + block_bytes.len());
    indexed.extend_from_slice(hash);
    indexed.extend_from_slice(&height.to_be_bytes());
    indexed.extend_from_slice(block_bytes);

    {
        let mut by_height = wtxn.open_table(BLOCKS_BY_HEIGHT)?;
        let mut by_hash = wtxn.open_table(BLOCKS_BY_HASH)?;
        let mut domains_t = wtxn.open_table(DOMAINS)?;
        let mut meta_t = wtxn.open_table(META)?;

        if let Some(previous) = by_height.get(height)? {
            let previous = previous.value();
            if previous == indexed.as_slice() {
                // Exact re-append of the same block: idempotent no-op.
                return Ok(());
            }
            return Err(StorageError::Conflict {
                what: "blocks_by_height",
                id: format!("{height}"),
            });
        }
        by_height.insert(height, &indexed[..])?;
        by_hash.insert(&hash[..], block_bytes)?;

        let mut new_domains: u64 = 0;
        for (domain, state) in state_deltas {
            let existed = domains_t.insert(&domain.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                new_domains += 1;
            }
        }
        if new_domains > 0 {
            let current = meta_u64(&meta_t, META_DOMAIN_COUNT, "domain_count")?;
            meta_t.insert(
                META_DOMAIN_COUNT,
                &(current + new_domains).to_be_bytes()[..],
            )?;
        }

        write_tip(&mut meta_t, height, hash)?;
    }
    Ok(())
}

impl NodeStore for RedbStore {
    fn append_block(&mut self, height: u64, hash: &[u8; 32], block_bytes: &[u8]) -> Result<()> {
        self.append_block_with_state(height, hash, block_bytes, &[])
    }

    fn append_block_with_state(
        &mut self,
        height: u64,
        hash: &[u8; 32],
        block_bytes: &[u8],
        state_deltas: &[(DomainId, DomainStateBytes)],
    ) -> Result<()> {
        let (tip_height, tip_hash) = self.tip_inner()?;
        if height == tip_height && hash == &tip_hash {
            // Idempotent re-append of the current tip.
            return Ok(());
        }
        let expected = tip_height
            .checked_add(1)
            .ok_or(StorageError::NonMonotonicHeight {
                expected: u64::MAX,
                got: height,
            })?;
        if height != expected {
            return Err(StorageError::NonMonotonicHeight {
                expected,
                got: height,
            });
        }
        let mut wtxn = self.db.begin_write()?;
        append_core(&mut wtxn, height, hash, block_bytes, state_deltas)?;
        wtxn.commit()?;
        Ok(())
    }

    fn block_at_height(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(BLOCKS_BY_HEIGHT)?;
        let Some(guard) = table.get(height)? else {
            return Ok(None);
        };
        let bytes = guard.value();
        if bytes.as_ref().len() < BLOCK_INDEX_HEADER {
            return Err(StorageError::Corrupted(format!(
                "blocks_by_height[{height}]: short index header"
            )));
        }
        Ok(Some(bytes[BLOCK_INDEX_HEADER..].to_vec()))
    }

    fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(BLOCKS_BY_HASH)?;
        Ok(table
            .get(hash.as_slice())?
            .map(|g| g.value().as_ref().to_vec()))
    }

    fn tip(&self) -> Result<(u64, [u8; 32])> {
        self.tip_inner()
    }

    fn put_domain_state(&mut self, domain: DomainId, state: DomainStateBytes) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        {
            let mut domains_t = wtxn.open_table(DOMAINS)?;
            let existed = domains_t.insert(&domain.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                let mut meta_t = wtxn.open_table(META)?;
                let current = meta_u64(&meta_t, META_DOMAIN_COUNT, "domain_count")?;
                meta_t.insert(META_DOMAIN_COUNT, &(current + 1).to_be_bytes()[..])?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    fn domain_state(&self, domain: &DomainId) -> Result<Option<DomainStateBytes>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(DOMAINS)?;
        match table.get(domain.as_bytes().as_slice())? {
            None => Ok(None),
            Some(guard) => {
                let (_, state) = decode_domain_entry(domain.as_bytes(), guard.value())?;
                Ok(Some(state))
            }
        }
    }

    fn domain_count(&self) -> Result<u64> {
        self.domain_count_inner()
    }

    fn iterate_domains(&self, after: Option<DomainId>, max: usize) -> Result<crate::DomainPage> {
        // DoS guard: clamp the requested page to the internal cap.
        let max = max.min(MAX_DOMAIN_PAGE);
        if max == 0 {
            return Ok((Vec::new(), after));
        }
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(DOMAINS)?;
        // Inclusive lower bound at `after` (when given); the entry equal
        // to `after` itself is skipped below, which yields a strictly
        // exclusive cursor even when `after` is not a stored key.
        let range = match after {
            None => table.range::<&[u8]>(..),
            Some(id) => {
                let start: &[u8] = id.as_bytes();
                table.range(start..)
            }
        }?;
        let mut out = Vec::new();
        let mut cursor = after;
        for entry in range {
            let (key, value) = entry?;
            let key = key.value();
            if let Some(previous) = after
                && key == previous.as_bytes()
            {
                continue;
            }
            let (domain, state) = decode_domain_entry(key, value.value())?;
            out.push((domain, state));
            cursor = Some(domain);
            if out.len() == max {
                break;
            }
        }
        Ok((out, cursor))
    }

    fn put_dht_cache(&mut self, domain: DomainId, record_bytes: &[u8]) -> Result<()> {
        // DoS guard: check BEFORE the write transaction, so an
        // oversized record never reaches redb.
        if record_bytes.len() > MAX_DHT_CACHE_ENTRY {
            return Err(StorageError::TooLarge {
                len: record_bytes.len(),
                max: MAX_DHT_CACHE_ENTRY,
            });
        }
        let wtxn = self.db.begin_write()?;
        {
            let mut table = wtxn.open_table(DHT_CACHE)?;
            table.insert(&domain.as_bytes()[..], record_bytes)?;
        }
        wtxn.commit()?;
        Ok(())
    }

    fn dht_cache(&self, domain: &DomainId) -> Result<Option<Vec<u8>>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(DHT_CACHE)?;
        Ok(table
            .get(domain.as_bytes().as_slice())?
            .map(|g| g.value().as_ref().to_vec()))
    }

    fn meta_get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(META)?;
        Ok(table.get(key)?.map(|g| g.value().as_ref().to_vec()))
    }

    fn meta_set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure_not_reserved(key)?;
        let wtxn = self.db.begin_write()?;
        {
            let mut table = wtxn.open_table(META)?;
            table.insert(key, value)?;
        }
        wtxn.commit()?;
        Ok(())
    }
}
