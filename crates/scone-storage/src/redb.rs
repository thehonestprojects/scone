//! `redb` backend of [`NodeStore`](crate::NodeStore).
//!
//! ## Tables
//!
//! | Table | Key | Value |
//! |---|---|---|
//! | `blocks_by_height` | `u64` height (ordered) | block hash `32` + height `8 BE` + canonical block bytes |
//! | `blocks_by_hash` | block hash (`32`) | canonical block bytes |
//! | `domains` | `DomainId` (`32`, ordered) | [`DomainStateBytes`] |
//! | `tlds` | `TldId` (`32`, ordered) | [`TldStateBytes`] (M7d) |
//! | `names_v3` (P0.2) | name-index key (`32`, ordered) | target id (`32`) |
//! | `name_reverse_v3` (P0.2) | target id (`32`, ordered) | `tag(1) ‖ canonical name` |
//! | `dht_cache` | `DomainId` (`32`) | encoded `SignedDnsRecord` |
//! | `meta` | `&[u8]` | `&[u8]` (tip, tip height, format version, domain counter, TLD counter) |
//! | `snapshot_v3_meta` | `0` (single slot) | `height(8 BE) + tip_hash(32)` (M6b boot snapshot) |
//! | `snapshot_v3_domains` | `DomainId` (`32`, ordered) | [`DomainStateBytes`] (frozen, M6b) |
//! | `snapshot_v3_tlds` | `TldId` (`32`, ordered) | [`TldStateBytes`] (frozen, M6b) |
//!
//! ## Guarantees
//!
//! - **ACID appends**: [`RedbStore::append_block_with_state`] writes
//!   the block in both indexes, the tip, the domain deltas, the TLD
//!   deltas and both counters in a single `WriteTransaction` — a crash
//!   mid-write leaves the previous consistent state (WAL-style
//!   commit). A block stored without its state updates (domains OR
//!   TLD registry) is impossible by construction.
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
use scone_core::{DomainId, TldId};

use crate::error::{Result, StorageError};
use crate::state_bytes::{decode_domain_entry, decode_tld_entry};
use crate::{
    DomainStateBytes, META_FORMAT_VERSION, META_TIP, NodeStore, STORAGE_FORMAT_VERSION,
    TldStateBytes,
};

/// `height -> hash(32) || height(8 BE) || block bytes`.
type BlocksByHeight = TableDefinition<'static, u64, &'static [u8]>;
/// `block_hash(32) -> block bytes`.
type BlocksByHash = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `DomainId(32) -> DomainStateBytes`.
type Domains = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `TldId(32) -> TldStateBytes` (M7d).
type Tlds = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// name-index key(32) -> target id(32) (P0.2).
type Names = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// target id(32) -> `tag(1) || canonical name` (P0.2).
type NameReverse = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `DomainId(32) -> encoded SignedDnsRecord`.
type DhtCache = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `meta key -> meta value`.
type Meta = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `snapshot key -> height(8 BE) || tip_hash(32)` (M6b, separate v3
/// tables so a pre-M6b store keeps loading with no snapshot).
type SnapshotMetaTable = TableDefinition<'static, u64, &'static [u8]>;
/// `DomainId(32) -> DomainStateBytes` — frozen snapshot state (M6b).
type SnapshotDomains = TableDefinition<'static, &'static [u8], &'static [u8]>;
/// `TldId(32) -> TldStateBytes` — frozen snapshot TLD registry (M6b).
type SnapshotTlds = TableDefinition<'static, &'static [u8], &'static [u8]>;

/// `meta` key of the cached tip height (keeps `tip()` O(1)).
const META_TIP_HEIGHT: &[u8] = b"tip_height";
/// `meta` key of the maintained domain-state counter (never `COUNT(*)`).
const META_DOMAIN_COUNT: &[u8] = b"domain_count";
/// `meta` key of the maintained TLD-state counter (never `COUNT(*)`) (M7d).
const META_TLD_COUNT: &[u8] = b"tld_count";

/// Maximum size of one cached DHT record (DoS guard): a hostile peer
/// must not be able to make the node persist unbounded blobs.
pub const MAX_DHT_CACHE_ENTRY: usize = 64 * 1024;

/// Internal cap on a single `iterate_domains` page (DoS guard): the
/// caller's `max` is clamped to this bound, so a bogus huge `max`
/// still yields a memory-bounded page.
pub const MAX_DOMAIN_PAGE: usize = 10_000;

/// Same DoS guard as [`MAX_DOMAIN_PAGE`], for `iterate_tlds` (M7d).
pub const MAX_TLD_PAGE: usize = 10_000;

/// State-snapshot cadence (M6b): every `SNAPSHOT_INTERVAL`-th append
/// (i.e. when the NEW tip height is a multiple of the interval) the
/// full canonical state is frozen into the `snapshot_v3_*` tables, in
/// the SAME transaction as the block. The snapshot therefore sits at
/// `tip - 1` at the oldest and can never equal the tip — at boot only
/// the blocks ABOVE the snapshot height are replayed, so the boot
/// cost is O(tip − H) with H within one interval of the tip.
///
/// 64 keeps the snapshot write amortized (one full-state freeze per
/// 64 blocks) while bounding the suffix replay to at most 63 blocks
/// plus the snapshot block itself.
pub const SNAPSHOT_INTERVAL: u64 = 64;

/// Rejects `meta` keys reserved for the store's internal
/// bookkeeping — clobbering them would silently corrupt the store.
fn ensure_not_reserved(key: &[u8]) -> Result<()> {
    if key == META_TIP
        || key == META_TIP_HEIGHT
        || key == META_FORMAT_VERSION
        || key == META_DOMAIN_COUNT
        || key == META_TLD_COUNT
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
const TLDS: Tlds = TableDefinition::new("tlds");
// P0.2 name index (v3 names so a pre-P0.2 store simply has no
// entries and resolves nothing until rebuilt).
const NAMES: Names = TableDefinition::new("names_v3");
const NAME_REVERSE: NameReverse = TableDefinition::new("name_reverse_v3");
const DHT_CACHE: DhtCache = TableDefinition::new("dht_cache");
const META: Meta = TableDefinition::new("meta");
// M6b snapshot tables: NEW names (v3 prefix), never written by a
// pre-M6b build — an old store simply has no snapshot and boots on
// the plain state load. The live `domains`/`tlds` tables are NOT
// touched by snapshotting: a stale snapshot can never corrupt the
// fast-load state.
const SNAPSHOT_META: SnapshotMetaTable = TableDefinition::new("snapshot_v3_meta");
const SNAPSHOT_DOMAINS: SnapshotDomains = TableDefinition::new("snapshot_v3_domains");
const SNAPSHOT_TLDS: SnapshotTlds = TableDefinition::new("snapshot_v3_tlds");

/// Value layout of `snapshot_v3_meta`: `height(8 BE) || tip_hash(32)`
/// (40 bytes exactly, strict decode).
const SNAPSHOT_META_LEN: usize = 8 + 32;

// ------------------------------------------------------------- P0.2 name index

/// Domain-separation prefix of the `names_v3` key hash.
pub const NAME_INDEX_VERSION: &[u8] = b"SCONE-NAME-IDX-V1";

/// Tag of a domain entry in `name_reverse_v3` values.
const NAME_TAG_DOMAIN: u8 = 0x01;
/// Tag of a TLD entry in `name_reverse_v3` values.
const NAME_TAG_TLD: u8 = 0x02;

/// Key of `names_v3`: `BLAKE3-256("SCONE-NAME-IDX-V1" || canonical_name)`.
///
/// The canonical name is deliberately NOT stored in clear in the
/// keyed table: the key is a pure function of the name, so the index
/// is reconstructible from the chain at any time
/// ([`RedbStore::rebuild_name_index`]) without any extra persisted
/// metadata. The name itself is stored once, in the companion
/// `name_reverse_v3` table (needed by the GC/removal path, which
/// only receives ids).
#[must_use]
pub fn name_index_key(canonical: &str) -> [u8; 32] {
    scone_crypto::hash256(&[NAME_INDEX_VERSION, canonical.as_bytes()])
}

/// `name_reverse_v3` value: `tag(1) || canonical name`.
#[must_use]
fn name_reverse_value(is_tld: bool, canonical: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + canonical.len());
    out.push(if is_tld {
        NAME_TAG_TLD
    } else {
        NAME_TAG_DOMAIN
    });
    out.extend_from_slice(canonical.as_bytes());
    out
}

/// Strictly decodes a `name_reverse_v3` value into `(is_tld, name)`.
fn decode_name_reverse(bytes: &[u8]) -> Result<(bool, String)> {
    let tag = *bytes
        .first()
        .ok_or_else(|| StorageError::Corrupted("name_reverse_v3: empty value".into()))?;
    let is_tld = match tag {
        NAME_TAG_DOMAIN => false,
        NAME_TAG_TLD => true,
        other => {
            return Err(StorageError::Corrupted(format!(
                "name_reverse_v3: unknown tag {other:#04x}"
            )));
        }
    };
    let name = std::str::from_utf8(&bytes[1..])
        .map_err(|_| StorageError::Corrupted("name_reverse_v3: name not UTF-8".into()))?;
    if name.is_empty() {
        return Err(StorageError::Corrupted(
            "name_reverse_v3: empty name".into(),
        ));
    }
    Ok((is_tld, name.to_owned()))
}

/// One P0.2 name-index binding: `(is_tld, canonical name, target id)`.
/// Re-exported alias — see [`crate::NameBinding`].
pub use crate::NameBinding;

/// Applies the P0.2 name-index deltas of one block inside the
/// caller's write transaction: upserts then removals, in both the
/// keyed index and the reverse table, so the pair stays consistent
/// atomically.
fn apply_name_deltas(
    names_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    reverse_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    upserts: &[NameBinding],
    removals: &[(bool, [u8; 32])],
) -> Result<()> {
    for binding in upserts {
        let key = name_index_key(&binding.name);
        names_t.insert(&key[..], &binding.target[..])?;
        reverse_t.insert(
            &binding.target[..],
            &name_reverse_value(binding.is_tld, &binding.name)[..],
        )?;
    }
    // Removals arrive as bare ids (the GC reports DomainIds, the TLD
    // revoke path TldIds): the canonical name is recovered from the
    // reverse table — still inside this transaction — to locate the
    // keyed entry, then both rows go together. The namespace tag is
    // informational here (the reverse row already carries it).
    for &(_is_tld, id) in removals {
        let Some(previous) = reverse_t.get(&id[..])? else {
            continue; // already absent: idempotent removal
        };
        let value = previous.value().to_vec();
        drop(previous);
        let (_, name) = decode_name_reverse(&value)?;
        names_t.remove(&name_index_key(&name)[..])?;
        reverse_t.remove(&id[..])?;
    }
    Ok(())
}

/// Removes one name-index entry by id inside the caller's write
/// transaction (P0.2). No-op when absent.
fn remove_name_entry(
    names_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    reverse_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    id: &[u8; 32],
) -> Result<()> {
    let value = match reverse_t.get(&id[..])? {
        Some(guard) => guard.value().to_vec(),
        None => return Ok(()), // already absent: idempotent removal
    };
    let (_, name) = decode_name_reverse(&value)?;
    names_t.remove(&name_index_key(&name)[..])?;
    reverse_t.remove(&id[..])?;
    Ok(())
}

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
            let _ = wtxn.open_table(TLDS)?;
            let _ = wtxn.open_table(NAMES)?;
            let _ = wtxn.open_table(NAME_REVERSE)?;
            let _ = wtxn.open_table(DHT_CACHE)?;
            let _ = wtxn.open_table(SNAPSHOT_META)?;
            let _ = wtxn.open_table(SNAPSHOT_DOMAINS)?;
            let _ = wtxn.open_table(SNAPSHOT_TLDS)?;
            let mut meta_t = wtxn.open_table(META)?;
            if meta_t.get(META_FORMAT_VERSION)?.is_none() {
                meta_t.insert(
                    META_FORMAT_VERSION,
                    &STORAGE_FORMAT_VERSION.to_be_bytes()[..],
                )?;
                write_tip(&mut meta_t, 0, &genesis_hash_bytes())?;
                meta_t.insert(META_DOMAIN_COUNT, &0u64.to_be_bytes()[..])?;
                meta_t.insert(META_TLD_COUNT, &0u64.to_be_bytes()[..])?;
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

    /// Maintained TLD-state counter (never a table scan) (M7d).
    fn tld_count_inner(&self) -> Result<u64> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(META)?;
        meta_u64(&table, META_TLD_COUNT, "tld_count")
    }

    /// Persists one domain state AND its name-index binding in a
    /// single transaction (P0.2 name-aware variant of
    /// [`NodeStore::put_domain_state`] — repair tools, snapshot
    /// restore paths that know the name).
    ///
    /// # Errors
    ///
    /// On I/O errors.
    pub fn put_domain_state_with_name(
        &mut self,
        domain: DomainId,
        state: DomainStateBytes,
        canonical_name: &str,
    ) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        {
            let mut domains_t = wtxn.open_table(DOMAINS)?;
            let existed = domains_t.insert(&domain.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                let mut meta_t = wtxn.open_table(META)?;
                let current = meta_u64(&meta_t, META_DOMAIN_COUNT, "domain_count")?;
                meta_t.insert(META_DOMAIN_COUNT, &(current + 1).to_be_bytes()[..])?;
            }
            let mut names_t = wtxn.open_table(NAMES)?;
            let mut reverse_t = wtxn.open_table(NAME_REVERSE)?;
            apply_name_deltas(
                &mut names_t,
                &mut reverse_t,
                &[NameBinding {
                    is_tld: false,
                    name: canonical_name.to_owned(),
                    target: *domain.as_bytes(),
                }],
                &[],
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Persists one TLD state AND its name-index binding in a single
    /// transaction (P0.2 name-aware variant of
    /// [`NodeStore::put_tld_state`]).
    ///
    /// # Errors
    ///
    /// On I/O errors.
    pub fn put_tld_state_with_name(
        &mut self,
        tld: TldId,
        state: TldStateBytes,
        tld_name: &str,
    ) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        {
            let mut tlds_t = wtxn.open_table(TLDS)?;
            let existed = tlds_t.insert(&tld.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                let mut meta_t = wtxn.open_table(META)?;
                let current = meta_u64(&meta_t, META_TLD_COUNT, "tld_count")?;
                meta_t.insert(META_TLD_COUNT, &(current + 1).to_be_bytes()[..])?;
            }
            let mut names_t = wtxn.open_table(NAMES)?;
            let mut reverse_t = wtxn.open_table(NAME_REVERSE)?;
            apply_name_deltas(
                &mut names_t,
                &mut reverse_t,
                &[NameBinding {
                    is_tld: true,
                    name: tld_name.to_owned(),
                    target: *tld.as_bytes(),
                }],
                &[],
            )?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Deletes one domain state AND its name-index entry in a single
    /// transaction (P0.2 — repair tools).
    ///
    /// # Errors
    ///
    /// On I/O errors or corrupted reverse-index bytes.
    pub fn remove_domain_state(&mut self, domain: &DomainId) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        {
            let mut domains_t = wtxn.open_table(DOMAINS)?;
            if domains_t.remove(&domain.as_bytes()[..])?.is_some() {
                let mut meta_t = wtxn.open_table(META)?;
                let current = meta_u64(&meta_t, META_DOMAIN_COUNT, "domain_count")?;
                let current = current
                    .checked_sub(1)
                    .ok_or_else(|| StorageError::Corrupted("domain_count underflow".into()))?;
                meta_t.insert(META_DOMAIN_COUNT, &current.to_be_bytes()[..])?;
            }
            let mut names_t = wtxn.open_table(NAMES)?;
            let mut reverse_t = wtxn.open_table(NAME_REVERSE)?;
            remove_name_entry(&mut names_t, &mut reverse_t, domain.as_bytes())?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Rebuilds the P0.2 name index from the persisted blocks (P0.2).
    ///
    /// The index is a pure function of the canonical chain: every
    /// `RegisterDomain`/`AssignDomain` transaction carries the
    /// canonical name in clear, so the whole index is reconstructed
    /// by scanning `blocks_by_height` from genesis to tip and
    /// replaying the bind/unbind decisions of each block — the same
    /// "rebuild from the chain" contract as
    /// [`rebuild_replay_index_from_store`](crate::integration::rebuild_replay_index_from_store).
    /// Names registered then GC'd (expired) or revoked are handled by
    /// applying, per block, the removals visible in the final state:
    /// a name is bound iff its target domain is still live at the
    /// end, or is a live TLD.
    ///
    /// Simple by design: one pass, one block in RAM at a time,
    /// memory bounded by the final index size written incrementally.
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if a stored block is missing or
    /// fails canonical decoding — the same bytes the chain was built
    /// from, a failure means the store is damaged.
    pub fn rebuild_name_index(&mut self) -> Result<()> {
        use scone_protocol::decode_complete;
        let (tip_height, _) = self.tip_inner()?;
        // Pass 1 (streamed): collect every (name → id) bind and every
        // id ever REMOVED from the live state (a registration followed
        // by GC/revoke). Names are small (≤ 253 bytes); the working
        // set is bounded by the number of distinct names ever seen.
        let mut binds: std::collections::HashMap<[u8; 32], (bool, String)> =
            std::collections::HashMap::new();
        for height in 1..=tip_height {
            let Some(bytes) = self.block_at_height(height)? else {
                return Err(StorageError::Corrupted(format!(
                    "blocks_by_height[{height}]: missing below tip"
                )));
            };
            let block: scone_protocol::Block = decode_complete(&bytes)
                .map_err(|e| StorageError::Corrupted(format!("block {height}: {e}")))?;
            for tx in &block.transactions {
                match tx {
                    scone_core::Transaction::RegisterDomain(r) => {
                        binds.insert(
                            *r.domain_id.as_bytes(),
                            (false, r.name.canonical().to_owned()),
                        );
                    }
                    scone_core::Transaction::AssignDomain(a) => {
                        binds.insert(
                            *a.domain_id.as_bytes(),
                            (false, a.name.canonical().to_owned()),
                        );
                    }
                    scone_core::Transaction::RegisterTld(t) => {
                        binds.insert(*t.tld_id.as_bytes(), (true, t.name.as_str().to_owned()));
                    }
                    _ => {}
                }
            }
        }
        // Pass 2: keep only live targets — the index must never point
        // at an absent domain (ghost-free invariant).
        let mut upserts = Vec::with_capacity(binds.len());
        {
            let rtxn = self.db.begin_read()?;
            let domains_ro = rtxn.open_table(DOMAINS)?;
            let tlds_ro = rtxn.open_table(TLDS)?;
            for (id, (is_tld, name)) in binds {
                let live = if is_tld {
                    tlds_ro.get(&id[..])?.is_some()
                } else {
                    domains_ro.get(&id[..])?.is_some()
                };
                if live {
                    upserts.push(NameBinding {
                        is_tld,
                        name,
                        target: id,
                    });
                }
            }
        }
        // Pass 3 (atomic): wipe and rewrite both tables in ONE
        // transaction — a crash leaves either the old or the new
        // complete index.
        let wtxn = self.db.begin_write()?;
        {
            let mut names_t = wtxn.open_table(NAMES)?;
            let mut reverse_t = wtxn.open_table(NAME_REVERSE)?;
            names_t.retain(|_, _| false)?;
            reverse_t.retain(|_, _| false)?;
            apply_name_deltas(&mut names_t, &mut reverse_t, &upserts, &[])?;
        }
        wtxn.commit()?;
        Ok(())
    }
}

/// Shared core of both append entry points: everything below runs in
/// the caller's single write transaction (ACID unit).
fn append_core(
    wtxn: &mut redb::WriteTransaction,
    height: u64,
    hash: &[u8; 32],
    block_bytes: &[u8],
    deltas: &crate::StateDelta,
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
        let mut tlds_t = wtxn.open_table(TLDS)?;
        let mut names_t = wtxn.open_table(NAMES)?;
        let mut name_reverse_t = wtxn.open_table(NAME_REVERSE)?;
        let mut meta_t = wtxn.open_table(META)?;

        // M6b state snapshot, BEFORE any delta of this block lands:
        // when the parent height (the just-completed tip) crosses a
        // multiple of the interval, freeze the parent state (the live
        // tables at this point still hold it) into the snapshot
        // tables, atomically with the block. The snapshot sits at
        // `height - 1` — strictly below the new tip, so a boot
        // restores it and replays at most `SNAPSHOT_INTERVAL` blocks.
        // Parent 0 (genesis) is excluded: genesis is never stored as
        // bytes and its state is empty by definition.
        if height > 1 && (height - 1).is_multiple_of(SNAPSHOT_INTERVAL) {
            let parent_height = height - 1;
            // The parent hash is read from the block index header
            // (`blocks_by_height` values are self-certifying: the
            // hash was recomputed by the caller when the parent was
            // accepted).
            let parent_hash: [u8; 32] = by_height
                .get(parent_height)?
                .map(|g| {
                    let v = g.value();
                    v.get(..32).and_then(|s| s.try_into().ok()).ok_or_else(|| {
                        StorageError::Corrupted(format!(
                            "blocks_by_height[{parent_height}]: short index header"
                        ))
                    })
                })
                .transpose()?
                .ok_or_else(|| {
                    StorageError::Corrupted(format!(
                        "blocks_by_height[{parent_height}]: missing below tip"
                    ))
                })?;
            drop(meta_t);
            drop(name_reverse_t);
            drop(names_t);
            drop(tlds_t);
            drop(domains_t);
            drop(by_hash);
            drop(by_height);
            snapshot_core(wtxn, parent_height, &parent_hash)?;
            let mut by_height = wtxn.open_table(BLOCKS_BY_HEIGHT)?;
            let mut by_hash = wtxn.open_table(BLOCKS_BY_HASH)?;
            let mut domains_t = wtxn.open_table(DOMAINS)?;
            let mut tlds_t = wtxn.open_table(TLDS)?;
            let mut names_t = wtxn.open_table(NAMES)?;
            let mut name_reverse_t = wtxn.open_table(NAME_REVERSE)?;
            let mut meta_t = wtxn.open_table(META)?;
            append_deltas(
                &mut by_height,
                &mut by_hash,
                &mut domains_t,
                &mut tlds_t,
                &mut names_t,
                &mut name_reverse_t,
                &mut meta_t,
                height,
                hash,
                block_bytes,
                &indexed,
                deltas,
            )?;
            return Ok(());
        }

        append_deltas(
            &mut by_height,
            &mut by_hash,
            &mut domains_t,
            &mut tlds_t,
            &mut names_t,
            &mut name_reverse_t,
            &mut meta_t,
            height,
            hash,
            block_bytes,
            &indexed,
            deltas,
        )
    }
}

/// Writes the block, its state deltas and the tip into tables opened
/// by the caller ([`append_core`] core — all inside one transaction).
#[allow(clippy::too_many_arguments)]
fn append_deltas(
    by_height: &mut redb::Table<'_, u64, &'static [u8]>,
    by_hash: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    domains_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    tlds_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    names_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    name_reverse_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    meta_t: &mut redb::Table<'_, &'static [u8], &'static [u8]>,
    height: u64,
    hash: &[u8; 32],
    block_bytes: &[u8],
    indexed: &[u8],
    deltas: &crate::StateDelta,
) -> Result<()> {
    let state_deltas = &deltas.domains;
    let tld_deltas = &deltas.tlds;
    let removed_domains = &deltas.removed_domains;
    let removed_tlds = &deltas.removed_tlds;
    {
        if let Some(previous) = by_height.get(height)? {
            let previous = previous.value();
            if previous == indexed {
                // Exact re-append of the same block: idempotent no-op.
                return Ok(());
            }
            return Err(StorageError::Conflict {
                what: "blocks_by_height",
                id: format!("{height}"),
            });
        }
        by_height.insert(height, indexed)?;
        by_hash.insert(&hash[..], block_bytes)?;

        let mut new_domains: u64 = 0;
        for (domain, state) in state_deltas {
            let existed = domains_t.insert(&domain.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                new_domains += 1;
            }
        }
        if new_domains > 0 {
            let current = meta_u64(meta_t, META_DOMAIN_COUNT, "domain_count")?;
            meta_t.insert(
                META_DOMAIN_COUNT,
                &(current + new_domains).to_be_bytes()[..],
            )?;
        }

        // TLD deltas land in the SAME transaction (M7d): a block can
        // never be stored without its TLD-registry changes.
        let mut new_tlds: u64 = 0;
        for (tld, state) in tld_deltas {
            let existed = tlds_t.insert(&tld.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                new_tlds += 1;
            }
        }
        if new_tlds > 0 {
            let current = meta_u64(meta_t, META_TLD_COUNT, "tld_count")?;
            meta_t.insert(META_TLD_COUNT, &(current + new_tlds).to_be_bytes()[..])?;
        }

        // M8b removals: expired domains (deterministic GC) and
        // revoked TLDs leave the store in the same ACID transaction —
        // a restart can never resurrect them.
        let mut removed_domain_count: u64 = 0;
        for domain in removed_domains {
            if domains_t.remove(&domain.as_bytes()[..])?.is_some() {
                removed_domain_count += 1;
            }
        }
        if removed_domain_count > 0 {
            let current = meta_u64(meta_t, META_DOMAIN_COUNT, "domain_count")?;
            let current = current
                .checked_sub(removed_domain_count)
                .ok_or_else(|| StorageError::Corrupted("domain_count underflow".into()))?;
            meta_t.insert(META_DOMAIN_COUNT, &current.to_be_bytes()[..])?;
        }
        let mut removed_tld_count: u64 = 0;
        for tld in removed_tlds {
            if tlds_t.remove(&tld.as_bytes()[..])?.is_some() {
                removed_tld_count += 1;
            }
        }
        if removed_tld_count > 0 {
            let current = meta_u64(meta_t, META_TLD_COUNT, "tld_count")?;
            let current = current
                .checked_sub(removed_tld_count)
                .ok_or_else(|| StorageError::Corrupted("tld_count underflow".into()))?;
            meta_t.insert(META_TLD_COUNT, &current.to_be_bytes()[..])?;
        }

        // P0.2 name index: upserts (register/assign paths, name known
        // from the tx) and removals (GC'd domains, revoked TLDs — bare
        // ids) land in the SAME transaction as the state writes above.
        // A crash can therefore never leave an index entry pointing
        // at an absent domain, nor a domain without its index entry.
        apply_name_deltas(
            names_t,
            name_reverse_t,
            &deltas.name_upserts,
            &deltas.name_removals,
        )?;

        write_tip(meta_t, height, hash)?;
    }
    Ok(())
}

/// Freezes the full canonical state into the `snapshot_v3_*` tables,
/// inside the caller's block transaction (M6b). Reads the LIVE
/// `domains`/`tlds` tables as they stand in this transaction (the
/// caller invokes it BEFORE writing the new block's deltas, so the
/// frozen state is exactly the state after block `height`).
///
/// A snapshot overwrites any previous one (single-slot design: one
/// meta row, two state tables, no accumulation — "pruning" of expired
/// snapshots is implicit).
fn snapshot_core(
    wtxn: &mut redb::WriteTransaction,
    height: u64,
    tip_hash: &[u8; 32],
) -> Result<()> {
    let mut meta_value = Vec::with_capacity(SNAPSHOT_META_LEN);
    meta_value.extend_from_slice(&height.to_be_bytes());
    meta_value.extend_from_slice(tip_hash);
    {
        let mut snap_meta = wtxn.open_table(SNAPSHOT_META)?;
        let mut snap_domains = wtxn.open_table(SNAPSHOT_DOMAINS)?;
        let mut snap_tlds = wtxn.open_table(SNAPSHOT_TLDS)?;
        let domains_ro = wtxn.open_table(DOMAINS)?;
        let tlds_ro = wtxn.open_table(TLDS)?;
        // Replace-in-place: clear then copy within the same ACID
        // transaction. redb write transactions see their own writes,
        // so `domains_ro` (opened before the snapshot tables are
        // touched) is not affected by the copy below — the live
        // tables are never modified here.
        snap_meta.retain(|_, _| false)?;
        snap_meta.insert(0u64, &meta_value[..])?;
        snap_domains.retain(|_, _| false)?;
        for entry in domains_ro.iter()? {
            let (key, value) = entry?;
            snap_domains.insert(key.value(), value.value())?;
        }
        snap_tlds.retain(|_, _| false)?;
        for entry in tlds_ro.iter()? {
            let (key, value) = entry?;
            snap_tlds.insert(key.value(), value.value())?;
        }
    }
    Ok(())
}

impl NodeStore for RedbStore {
    fn append_block(&mut self, height: u64, hash: &[u8; 32], block_bytes: &[u8]) -> Result<()> {
        self.append_block_with_state(height, hash, block_bytes, &crate::StateDelta::empty())
    }

    fn append_block_with_state(
        &mut self,
        height: u64,
        hash: &[u8; 32],
        block_bytes: &[u8],
        deltas: &crate::StateDelta,
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
        append_core(&mut wtxn, height, hash, block_bytes, deltas)?;
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

    fn put_tld_state(&mut self, tld: TldId, state: TldStateBytes) -> Result<()> {
        let wtxn = self.db.begin_write()?;
        {
            let mut tlds_t = wtxn.open_table(TLDS)?;
            let existed = tlds_t.insert(&tld.as_bytes()[..], state.as_encoded())?;
            if existed.is_none() {
                let mut meta_t = wtxn.open_table(META)?;
                let current = meta_u64(&meta_t, META_TLD_COUNT, "tld_count")?;
                meta_t.insert(META_TLD_COUNT, &(current + 1).to_be_bytes()[..])?;
            }
        }
        wtxn.commit()?;
        Ok(())
    }

    fn tld_state(&self, tld: &TldId) -> Result<Option<TldStateBytes>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(TLDS)?;
        match table.get(tld.as_bytes().as_slice())? {
            None => Ok(None),
            Some(guard) => {
                let (_, state) = decode_tld_entry(tld.as_bytes(), guard.value())?;
                Ok(Some(state))
            }
        }
    }

    fn tld_count(&self) -> Result<u64> {
        self.tld_count_inner()
    }

    fn iterate_tlds(&self, after: Option<TldId>, max: usize) -> Result<crate::TldPage> {
        // DoS guard: clamp the requested page to the internal cap.
        let max = max.min(MAX_TLD_PAGE);
        if max == 0 {
            return Ok((Vec::new(), after));
        }
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(TLDS)?;
        // Same strictly-exclusive-cursor trick as `iterate_domains`.
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
            let (tld, state) = decode_tld_entry(key, value.value())?;
            out.push((tld, state));
            cursor = Some(tld);
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

    fn snapshot_meta(&self) -> Result<Option<crate::SnapshotMeta>> {
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(SNAPSHOT_META)?;
        let Some(guard) = table.get(0u64)? else {
            return Ok(None);
        };
        let bytes = guard.value();
        if bytes.len() != SNAPSHOT_META_LEN {
            return Err(StorageError::Corrupted(format!(
                "snapshot_v3_meta: not {SNAPSHOT_META_LEN} bytes"
            )));
        }
        let height = u64::from_be_bytes(bytes[..8].try_into().expect("len checked"));
        let tip_hash: [u8; 32] = bytes[8..].try_into().expect("len checked");
        Ok(Some(crate::SnapshotMeta { height, tip_hash }))
    }

    fn snapshot_domains(&self, after: Option<DomainId>, max: usize) -> Result<crate::DomainPage> {
        self.snapshot_domains_inner(after, max)
    }

    fn snapshot_tlds(&self, after: Option<TldId>, max: usize) -> Result<crate::TldPage> {
        self.snapshot_tlds_inner(after, max)
    }

    fn resolve_name(&self, canonical: &str) -> Result<Option<DomainId>> {
        let rtxn = self.db.begin_read()?;
        let names = rtxn.open_table(NAMES)?;
        let reverse = rtxn.open_table(NAME_REVERSE)?;
        let Some(id) = names
            .get(name_index_key(canonical).as_slice())?
            .and_then(|g| <[u8; 32]>::try_from(g.value()).ok())
        else {
            return Ok(None);
        };
        // Namespace check (strict): the entry must be a DOMAIN, not a
        // TLD — `resolve_tld` owns that half of the keyspace.
        let Some(previous) = reverse.get(&id[..])? else {
            return Err(StorageError::Corrupted(
                "name_reverse_v3: missing entry for resolved id".to_string(),
            ));
        };
        let (is_tld, _) = decode_name_reverse(previous.value())?;
        if is_tld {
            return Ok(None);
        }
        Ok(Some(DomainId::from_bytes(id)))
    }

    fn resolve_tld(&self, tld: &str) -> Result<Option<TldId>> {
        let rtxn = self.db.begin_read()?;
        let names = rtxn.open_table(NAMES)?;
        let reverse = rtxn.open_table(NAME_REVERSE)?;
        let Some(id) = names
            .get(name_index_key(tld).as_slice())?
            .and_then(|g| <[u8; 32]>::try_from(g.value()).ok())
        else {
            return Ok(None);
        };
        let Some(previous) = reverse.get(&id[..])? else {
            return Err(StorageError::Corrupted(
                "name_reverse_v3: missing entry for resolved id".into(),
            ));
        };
        let (is_tld, _) = decode_name_reverse(previous.value())?;
        if !is_tld {
            return Ok(None);
        }
        Ok(Some(TldId::from_bytes(id)))
    }
}

impl RedbStore {
    /// Reads up to `max` snapshot domain states with id strictly
    /// greater than `after` (same cursor contract as
    /// [`NodeStore::iterate_domains`], over the frozen snapshot
    /// tables) (M6b).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if an entry fails strict decoding.
    fn snapshot_domains_inner(
        &self,
        after: Option<DomainId>,
        max: usize,
    ) -> Result<crate::DomainPage> {
        let max = max.min(MAX_DOMAIN_PAGE);
        if max == 0 {
            return Ok((Vec::new(), after));
        }
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(SNAPSHOT_DOMAINS)?;
        let range = match after {
            None => table.range::<&[u8]>(..)?,
            Some(id) => {
                let start: &[u8] = id.as_bytes();
                table.range(start..)?
            }
        };
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

    /// Reads up to `max` snapshot TLD states with id strictly greater
    /// than `after` (same cursor contract over the frozen snapshot
    /// TLD registry) (M6b).
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] if an entry fails strict decoding.
    fn snapshot_tlds_inner(&self, after: Option<TldId>, max: usize) -> Result<crate::TldPage> {
        let max = max.min(MAX_TLD_PAGE);
        if max == 0 {
            return Ok((Vec::new(), after));
        }
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(SNAPSHOT_TLDS)?;
        let range = match after {
            None => table.range::<&[u8]>(..)?,
            Some(id) => {
                let start: &[u8] = id.as_bytes();
                table.range(start..)?
            }
        };
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
            let (tld, state) = decode_tld_entry(key, value.value())?;
            out.push((tld, state));
            cursor = Some(tld);
            if out.len() == max {
                break;
            }
        }
        Ok((out, cursor))
    }
}
