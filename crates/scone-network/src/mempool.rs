//! Bounded mempool: validated transactions awaiting block production.
//!
//! Capacity-bounded and deduplicated by [`TxId`]: a duplicate
//! transaction is silently ignored (idempotent submit), a full pool
//! rejects new entries with [`NetworkError::LimitExceeded`]. No
//! ordering guarantees beyond insertion order (fees are future work).

use std::collections::HashMap;

use scone_blockchain::TxId;

use crate::error::{NetworkError, Result};

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
}
