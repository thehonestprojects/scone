//! Bounded mempool: validated transactions awaiting block production.
//!
//! Capacity-bounded and deduplicated by [`TxId`]: a duplicate
//! transaction is silently ignored (idempotent submit), a full pool
//! rejects new entries with [`NetworkError::LimitExceeded`]. No
//! ordering guarantees beyond insertion order (fees are future work).

use std::collections::HashMap;

use scone_blockchain::TxId;

use crate::error::{NetworkError, Result};

/// Pending-transaction cap **per domain** (economic anti-spam, ported
/// from the .bak `MAX_PENDING_PER_DOMAIN`): an owner cannot saturate
/// the mempool for free with UPDATE/TRANSFER-type operations —
/// beyond this many pending transactions targeting the same
/// `DomainId` (or `TldId` for the TLD family), new ones are rejected.
/// Multiplying domains costs a REGISTER (PoW), which keeps spam
/// proportional to proof-of-work. Large enough for a reorg
/// (REGISTER+UPDATE+TRANSFER+UPDATE re-inserted), low enough to
/// matter.
pub const MAX_PENDING_PER_DOMAIN: usize = 4;

/// Byte key identifying the target namespace of a transaction for
/// the per-domain cap: `DomainId` for domain operations, `TldId` for
/// the TLD family (`RegisterTld`/`TransferTld`/`RevokeTld`/
/// `SetTldOpen`). TLD and domain id spaces are disjoint by
/// derivation, so one `[u8; 32]` space is enough.
#[must_use]
pub fn domain_key(tx: &scone_core::Transaction) -> Option<[u8; 32]> {
    use scone_core::Transaction;
    match tx {
        Transaction::RegisterDomain(r) => Some(*r.domain_id.as_bytes()),
        Transaction::UpdateDomain(u) => Some(*u.domain_id.as_bytes()),
        Transaction::AssignDomain(a) => Some(*a.domain_id.as_bytes()),
        Transaction::RenewDomain(r) => Some(*r.domain_id.as_bytes()),
        Transaction::TransferDomain(t) => Some(*t.domain_id.as_bytes()),
        Transaction::RegisterTld(t) => Some(*t.tld_id.as_bytes()),
        Transaction::TransferTld(t) => Some(*t.tld_id.as_bytes()),
        Transaction::RevokeTld(r) => Some(*r.tld_id.as_bytes()),
        Transaction::SetTldOpen(s) => Some(*s.tld_id.as_bytes()),
        // M9: a slash targets an anchor key, not a namespace — no
        // per-domain cap (bounded by MAX_TXS_PER_BLOCK like any tx).
        Transaction::Slash(_) => None,
    }
}

/// A bounded set of validated transactions.
#[derive(Debug)]
pub struct Mempool {
    capacity: usize,
    /// Insertion-ordered ids (production consumes from the front).
    order: Vec<TxId>,
    entries: HashMap<TxId, scone_core::Transaction>,
}

impl Mempool {
    /// New mempool with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: Vec::new(),
            entries: HashMap::new(),
        }
    }

    /// Capacity of the pool.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of pooled transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts a transaction (already validated by the caller).
    ///
    /// Deduplicates by [`TxId`]: re-submitting a pooled transaction is
    /// a no-op returning `Ok(false)`. Callers must broadcast the
    /// transaction **only when `Ok(true)` is returned** — relaying a
    /// duplicate re-enters an endless gossip loop on cycles of 3+
    /// peers (audit M4, H2).
    ///
    /// # Errors
    ///
    /// [`NetworkError::LimitExceeded`] when the pool is full.
    pub fn insert(&mut self, id: TxId, tx: scone_core::Transaction) -> Result<bool> {
        if self.entries.contains_key(&id) {
            return Ok(false);
        }
        if self.entries.len() >= self.capacity {
            return Err(NetworkError::LimitExceeded("mempool capacity"));
        }
        self.order.push(id);
        self.entries.insert(id, tx);
        Ok(true)
    }

    /// Whether `id` is pooled.
    #[must_use]
    pub fn contains(&self, id: &TxId) -> bool {
        self.entries.contains_key(id)
    }

    /// Number of pooled transactions targeting `key` (per-domain
    /// anti-spam cap, see [`MAX_PENDING_PER_DOMAIN`]).
    #[must_use]
    pub fn count_for_domain(&self, key: [u8; 32]) -> usize {
        self.entries
            .values()
            .filter(|tx| domain_key(tx) == Some(key))
            .count()
    }

    /// Drains up to `max` transactions in insertion order
    /// (production path).
    #[must_use]
    pub fn drain_up_to(&mut self, max: usize) -> Vec<scone_core::Transaction> {
        let take = max.min(self.order.len());
        let ids: Vec<TxId> = self.order.drain(..take).collect();
        ids.iter()
            .filter_map(|id| self.entries.remove(id))
            .collect()
    }

    /// Removes `id` from the pool (e.g. the tx landed in a block).
    pub fn remove(&mut self, id: &TxId) {
        if self.entries.remove(id).is_some() {
            self.order.retain(|other| other != id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_core::{DomainName, Proof, RegisterDomain};
    use scone_crypto::{Signature, SigningKey};

    fn tx(name: &str, seed: u8) -> (TxId, scone_core::Transaction) {
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned =
            scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                Proof::from_bytes(Vec::new()),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ));
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        let signed = match unsigned {
            scone_core::Transaction::RegisterDomain(mut r) => {
                r.signature = sk.sign(&payload);
                scone_core::Transaction::RegisterDomain(r)
            }
            _ => unreachable!(),
        };
        let id = scone_blockchain::transaction_id(&signed).unwrap();
        (id, signed)
    }

    #[test]
    fn inserts_and_drains_in_order() {
        let (id_a, a) = tx("a.uip", 1);
        let (id_b, b) = tx("b.uip", 2);
        let mut pool = Mempool::new(10);
        assert!(pool.is_empty());
        assert!(pool.insert(id_a, a).unwrap());
        assert!(pool.insert(id_b, b).unwrap());
        assert_eq!(pool.len(), 2);
        assert!(pool.contains(&id_a));
        let drained = pool.drain_up_to(1);
        assert_eq!(drained.len(), 1);
        assert!(!pool.contains(&id_a));
        assert!(pool.contains(&id_b));
        let rest = pool.drain_up_to(10);
        assert_eq!(rest.len(), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn duplicate_insert_is_a_no_op() {
        let (id, t) = tx("a.uip", 1);
        let mut pool = Mempool::new(10);
        assert!(pool.insert(id, t.clone()).unwrap());
        assert!(
            !pool.insert(id, t).unwrap(),
            "duplicate reports not-inserted"
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn full_pool_rejects() {
        let mut pool = Mempool::new(1);
        let (id_a, a) = tx("a.uip", 1);
        let (id_b, b) = tx("b.uip", 2);
        pool.insert(id_a, a).unwrap();
        assert!(matches!(
            pool.insert(id_b, b),
            Err(NetworkError::LimitExceeded("mempool capacity"))
        ));
    }

    #[test]
    fn remove_reconciles_order() {
        let (id_a, a) = tx("a.uip", 1);
        let (id_b, b) = tx("b.uip", 2);
        let mut pool = Mempool::new(10);
        assert!(pool.insert(id_a, a).unwrap());
        assert!(pool.insert(id_b, b).unwrap());
        pool.remove(&id_a);
        assert_eq!(pool.len(), 1);
        let drained = pool.drain_up_to(10);
        assert_eq!(drained.len(), 1);
    }

    // ---- per-domain anti-spam cap (ported from the .bak) ----

    #[test]
    fn domain_key_separates_namespaces() {
        use scone_core::{DomainName, TldName};
        let register = tx("a.uip", 1).1;
        let update = update_tx("a.uip", 1).1;
        let tld = register_tld("uip", 1).1;
        let expected =
            *scone_core::DomainId::from_name(&DomainName::new("a.uip").unwrap()).as_bytes();
        assert_eq!(domain_key(&register), Some(expected));
        assert_eq!(domain_key(&update), Some(expected));
        // TLD family keys on tld_id — a different id space by
        // derivation (no collision with domain ids).
        let tld_expected = *scone_core::TldId::from_tld(&TldName::new("uip").unwrap()).as_bytes();
        assert_eq!(domain_key(&tld), Some(tld_expected));
        assert_ne!(domain_key(&tld), Some(expected));
        // Different names -> different keys.
        let other = tx("b.uip", 1).1;
        assert_ne!(domain_key(&other), Some(expected));
    }

    #[test]
    fn count_for_domain_counts_pending_per_namespace() {
        let mut pool = Mempool::new(10);
        // Two distinct transactions (different signers, different
        // TxIds) targeting the SAME domain…
        let (id_a1, a1) = tx("a.uip", 1);
        let (id_a2, a2) = tx("a.uip", 2);
        // …and one on another domain.
        let (id_b, b) = tx("b.uip", 3);
        assert!(pool.insert(id_a1, a1).unwrap());
        assert!(pool.insert(id_a2, a2).unwrap());
        assert!(pool.insert(id_b, b).unwrap());
        let key_a = domain_key(&tx("a.uip", 1).1).unwrap();
        assert_eq!(pool.count_for_domain(key_a), 2);
        let key_b = domain_key(&tx("b.uip", 3).1).unwrap();
        assert_eq!(pool.count_for_domain(key_b), 1);
        // The cap threshold itself: MAX_PENDING_PER_DOMAIN pending on
        // one domain is reachable, one more must be refused by the
        // caller (accept_transaction).
        assert_eq!(MAX_PENDING_PER_DOMAIN, 4);
    }

    /// Signed UpdateDomain fixture (same domain as `tx`).
    fn update_tx(name: &str, seed: u8) -> (TxId, scone_core::Transaction) {
        use scone_core::{DomainId, DomainName, RecordHash, UpdateDomain};
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned = scone_core::Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            DomainId::from_name(&DomainName::new(name).unwrap()),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        let signed = match unsigned {
            scone_core::Transaction::UpdateDomain(mut u) => {
                u.signature = sk.sign(&payload);
                scone_core::Transaction::UpdateDomain(u)
            }
            _ => unreachable!(),
        };
        let id = scone_blockchain::transaction_id(&signed).unwrap();
        (id, signed)
    }

    /// Signed RegisterTld fixture (empty proof — `transaction_id`
    /// only needs canonical encodability).
    fn register_tld(tld: &str, seed: u8) -> (TxId, scone_core::Transaction) {
        use scone_core::{RegisterTld, TldName};
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned = scone_core::Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldName::new(tld).unwrap(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        let signed = match unsigned {
            scone_core::Transaction::RegisterTld(mut t) => {
                t.signature = sk.sign(&payload);
                scone_core::Transaction::RegisterTld(t)
            }
            _ => unreachable!(),
        };
        let id = scone_blockchain::transaction_id(&signed).unwrap();
        (id, signed)
    }
}
