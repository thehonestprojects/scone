//! Scalable key-value backend for the canonical chain state.
//!
//! # Why a trait
//!
//! The chain state targets 250+ billion potential domains: the live
//! state must NEVER be held as a whole in RAM. [`ChainState`](crate::
//! state::ChainState) therefore accesses domains and TLDs ONLY
//! through the [`StateBackend`] trait below — point reads by key,
//! journaled writes, deterministic deletes — and keeps just bounded
//! auxiliary indexes in memory (owner pool, expiration queue, grace
//! windows; each justified at its definition site in `state.rs`).
//!
//! The protocol and the consensus depend on the TRAIT only, never on
//! a concrete store: `scone-blockchain` deliberately carries no
//! storage dependency (no redb — the crate rule "no storage backend"
//! holds). [`MemoryBackend`] wraps the former `HashMap`s for
//! development, tests and as the reference semantics; a TiKV (or
//! sharded KV, or redb-backed) implementation can be provided later
//! from another crate without touching one consensus rule.
//!
//! # Determinism contract
//!
//! - keys are fixed-width 32-byte ids ([`Pkey`], the raw
//!   `DomainId`/`TldId` bytes — disjoint by derivation prefix);
//! - values are opaque entry bytes produced/consumed by
//!   [`ChainState`] (fixed-size `SCONE-ENTRY-DOM-V1` /
//!   `SCONE-ENTRY-TLD-V1` encodings, see `state.rs`);
//! - `range` iterates in **ascending key order** (a BTreeMap in the
//!   reference implementation; any backend must guarantee it) — the
//!   canonical V2 archive fold and the tests rely on it;
//! - every operation is deterministic: two backends fed the same
//!   operations answer identically. No clocks, no ambient state.
//!
//! ## Ram budget (why this scales)
//!
//! With a disk/remote backend, the steady-state RAM of the chain
//! layer is `O(distinct owners + pending expirations + grace
//! windows + undo journal)`, all bounded independently of the
//! domain count (see `docs/technical/blockchain.md`, section
//! "État scalable"). The in-RAM structures are maintained by the
//! same undo journal as the state itself, so a rollback restores
//! them exactly.

use std::collections::BTreeMap;

use scone_core::{DomainId, TldId};

/// Backend key: the raw 32 bytes of a [`DomainId`] or [`TldId`].
///
/// The two id spaces are disjoint by derivation prefix (see
/// `/docs/general/naming.md`), so ONE ordered key space serves both
/// maps — a backend implementation never needs to distinguish them.
pub type Pkey = [u8; 32];

/// Ordered key-value backend for the canonical chain state.
///
/// See the module docs for the determinism contract. All methods are
/// infallible in the reference implementation; a remote backend
/// (TiKV & co.) may make them fallible later — until then the trait
/// stays simple and `ChainState` never panics on untrusted input
/// (values it reads back are its own encodings).
pub trait StateBackend: Default + Send {
    /// Point read of one entry.
    fn get(&self, key: &Pkey) -> Option<Vec<u8>>;

    /// Insert-or-replace one entry (journaled by `ChainState`, which
    /// records the prior value for the rollback).
    fn put(&mut self, key: Pkey, value: Vec<u8>);

    /// Remove one entry if present (journaled by `ChainState`).
    fn delete(&mut self, key: &Pkey);

    /// Ascending-key iteration over `from` (inclusive, `None` =
    /// start) up to `limit` entries. Returns the page and the next
    /// cursor (`None` when exhausted). Same paging contract as the
    /// node store's `snapshot_domains`/`iterate_domains`: a caller
    /// scanning the whole space pages with the returned cursor until
    /// a short page.
    fn range(&self, from: Option<&Pkey>, limit: usize) -> (Vec<(Pkey, Vec<u8>)>, Option<Pkey>);

    /// Number of entries (diagnostics, tests).
    fn len(&self) -> usize;

    /// Whether the backend holds no entry.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl StateBackend for BTreeMap<Pkey, Vec<u8>> {
    fn get(&self, key: &Pkey) -> Option<Vec<u8>> {
        BTreeMap::get(self, key).cloned()
    }

    fn put(&mut self, key: Pkey, value: Vec<u8>) {
        self.insert(key, value);
    }

    fn delete(&mut self, key: &Pkey) {
        self.remove(key);
    }

    fn range(&self, from: Option<&Pkey>, limit: usize) -> (Vec<(Pkey, Vec<u8>)>, Option<Pkey>) {
        use std::ops::Bound;
        let mut page = Vec::new();
        let mut cursor = None;
        let start: (Bound<Pkey>, Bound<Pkey>) = match from {
            Some(k) => (Bound::Included(*k), Bound::Unbounded),
            None => (Bound::Unbounded, Bound::Unbounded),
        };
        for (k, v) in self.range(start).take(limit.saturating_add(1)) {
            if page.len() == limit {
                cursor = Some(*k);
                break;
            }
            page.push((*k, v.clone()));
        }
        (page, cursor)
    }

    fn len(&self) -> usize {
        BTreeMap::len(self)
    }
}

/// Reference in-memory backend: the former `HashMap`s of
/// [`ChainState`](crate::state::ChainState), merged into one ordered
/// map (domain and TLD ids share the key space, disjoint by
/// derivation prefix).
///
/// Semantics reference for every future backend (TiKV, redb-backed,
/// sharded): same operations, same ascending order, same answers.
/// Development and tests run on it; it is obviously NOT the scalable
/// deployment — swapping the backend changes zero consensus rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryBackend {
    entries: BTreeMap<Pkey, Vec<u8>>,
}

impl MemoryBackend {
    /// Empty backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateBackend for MemoryBackend {
    fn get(&self, key: &Pkey) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }

    fn put(&mut self, key: Pkey, value: Vec<u8>) {
        self.entries.insert(key, value);
    }

    fn delete(&mut self, key: &Pkey) {
        self.entries.remove(key);
    }

    fn range(&self, from: Option<&Pkey>, limit: usize) -> (Vec<(Pkey, Vec<u8>)>, Option<Pkey>) {
        StateBackend::range(&self.entries, from, limit)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Key of a domain entry (raw `DomainId` bytes).
#[must_use]
pub fn domain_key(id: &DomainId) -> Pkey {
    *id.as_bytes()
}

/// Key of a TLD entry (raw `TldId` bytes).
#[must_use]
pub fn tld_key(id: &TldId) -> Pkey {
    *id.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_backend_is_empty() {
        let b = MemoryBackend::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        assert_eq!(b.get(&[0; 32]), None);
    }

    #[test]
    fn put_get_delete_roundtrip() {
        let mut b = MemoryBackend::new();
        b.put([1; 32], vec![0xaa, 0xbb]);
        assert_eq!(b.get(&[1; 32]), Some(vec![0xaa, 0xbb]));
        assert_eq!(b.len(), 1);
        b.delete(&[1; 32]);
        assert_eq!(b.get(&[1; 32]), None);
        assert!(b.is_empty());
        // Deleting a missing key is a no-op, never a panic.
        b.delete(&[1; 32]);
    }

    #[test]
    fn put_replaces() {
        let mut b = MemoryBackend::new();
        b.put([7; 32], vec![1]);
        b.put([7; 32], vec![2, 3]);
        assert_eq!(b.get(&[7; 32]), Some(vec![2, 3]));
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn range_is_ascending_and_pageable() {
        let mut b = MemoryBackend::new();
        // Keys of increasing value (first byte varies).
        for i in 0u8..10 {
            let mut k = [0u8; 32];
            k[0] = i;
            b.put(k, vec![i]);
        }
        // Full scan by pages of 3: ascending, no loss, no overlap.
        let mut seen: Vec<u8> = Vec::new();
        let mut cursor: Option<Pkey> = None;
        loop {
            let (page, next) = b.range(cursor.as_ref(), 3);
            for (k, v) in page {
                assert_eq!(k[0], v[0]);
                seen.push(k[0]);
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(seen, (0u8..10).collect::<Vec<_>>());
    }

    #[test]
    fn range_from_is_inclusive_and_limit_zero_is_empty() {
        let mut b = MemoryBackend::new();
        for i in 0u8..5 {
            let mut k = [0u8; 32];
            k[0] = i;
            b.put(k, vec![i]);
        }
        let mut from = [0u8; 32];
        from[0] = 2;
        let (page, next) = b.range(Some(&from), 2);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].0[0], 2);
        assert_eq!(page[1].0[0], 3);
        assert_eq!(next.as_ref().map(|k| k[0]), Some(4));
        let (empty, next) = b.range(None, 0);
        assert!(empty.is_empty());
        assert_eq!(next.as_ref().map(|k| k[0]), Some(0));
    }

    #[test]
    fn domain_and_tld_keys_are_raw_ids() {
        use scone_core::{DomainName, TldName};
        let d = DomainId::from_name(&DomainName::new("a.uip").unwrap());
        let t = TldId::from_tld(&TldName::new("uip").unwrap());
        assert_eq!(domain_key(&d), *d.as_bytes());
        assert_eq!(tld_key(&t), *t.as_bytes());
    }
}
