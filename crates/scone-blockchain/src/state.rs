//! Canonical chain state and transaction application rules.

use std::collections::HashMap;

use scone_core::{DomainId, OwnerId, RecordHash, Transaction};

use crate::error::{BlockchainError, Result};

/// On-chain state of one registered domain.
///
/// Right after a `Register`: `sequence == 0` and `record_hash == None`
/// (a registration claims the name; the first `Update` publishes
/// records and sets `sequence` to 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainState {
    /// Current owner.
    pub owner: OwnerId,
    /// Latest applied `Update` sequence (0 right after registration).
    pub sequence: u64,
    /// Current on-chain commitment to the DNS record set, once an
    /// `Update` has been applied.
    pub record_hash: Option<RecordHash>,
}

/// Authoritative in-memory state of a chain.
///
/// Direct `DomainId -> DomainState` access, no full scan (ready for
/// billions of domains; a storage backend will replace the map later,
/// the rules stay here). Domain names are never used as keys: the
/// 32-byte [`DomainId`] only.
///
/// Two nodes starting from the same state and applying exactly the same
/// blocks reach exactly equal [`ChainState`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainState {
    domains: HashMap<DomainId, DomainState>,
}

impl ChainState {
    /// Empty state (genesis state: no domain registered).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registered domains.
    #[must_use]
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether no domain is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Current state of `domain`, if registered.
    #[must_use]
    pub fn domain(&self, domain: &DomainId) -> Option<&DomainState> {
        self.domains.get(domain)
    }

    /// Applies `tx` to the state, deterministically and atomically (on
    /// error the state is left unchanged).
    ///
    /// Rules (see `/docs/blockchain.md`):
    ///
    /// - **Register**: the domain must be free; it becomes
    ///   `{ owner, sequence: 0, record_hash: None }`. The proof is not
    ///   interpreted here — that is a consensus concern
    ///   (see [`crate::Consensus`]).
    /// - **Update**: the domain must exist, `tx.owner` must be the
    ///   current owner, and `tx.sequence` must be exactly
    ///   `current + 1`; `record_hash` becomes the current commitment.
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub fn apply(&mut self, tx: &Transaction) -> Result<()> {
        tx.validate()?;
        match tx {
            Transaction::Register(register) => {
                if self.domains.contains_key(&register.domain_id) {
                    return Err(BlockchainError::DomainAlreadyRegistered);
                }
                self.domains.insert(
                    register.domain_id,
                    DomainState {
                        owner: register.owner,
                        sequence: 0,
                        record_hash: None,
                    },
                );
            }
            Transaction::Update(update) => {
                let state = self
                    .domains
                    .get_mut(&update.domain_id)
                    .ok_or(BlockchainError::UnknownDomain)?;
                if state.owner != update.owner {
                    return Err(BlockchainError::NotOwner);
                }
                let expected =
                    state
                        .sequence
                        .checked_add(1)
                        .ok_or(BlockchainError::InvalidSequence {
                            expected: u64::MAX,
                            got: update.sequence,
                        })?;
                if update.sequence != expected {
                    return Err(BlockchainError::InvalidSequence {
                        expected,
                        got: update.sequence,
                    });
                }
                state.sequence = expected;
                state.record_hash = Some(update.record_hash);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_core::{DomainName, Proof, Register, Update};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    fn owner(byte: u8) -> OwnerId {
        OwnerId::from_bytes([byte; 32])
    }

    fn register(name: &str, owner_byte: u8) -> Transaction {
        Transaction::Register(Register {
            domain_id: domain_id(name),
            owner: owner(owner_byte),
            timestamp: 1,
            proof: Proof::from_bytes(Vec::new()),
        })
    }

    fn update(name: &str, owner_byte: u8, sequence: u64) -> Transaction {
        Transaction::Update(Update {
            domain_id: domain_id(name),
            owner: owner(owner_byte),
            sequence,
            record_hash: RecordHash::from_bytes([sequence as u8; 32]),
            timestamp: 1,
        })
    }

    #[test]
    fn new_state_is_empty() {
        let state = ChainState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert!(state.domain(&domain_id("example.uip")).is_none());
    }

    #[test]
    fn register_creates_initial_domain_state() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();
        let domain = state.domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.owner, owner(1));
        assert_eq!(domain.sequence, 0);
        assert_eq!(domain.record_hash, None);
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn double_register_is_rejected() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();
        assert_eq!(
            state.apply(&register("example.uip", 1)),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
        // Even by a different owner: the domain is taken.
        assert_eq!(
            state.apply(&register("example.uip", 2)),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn update_unknown_domain_is_rejected() {
        let mut state = ChainState::new();
        assert_eq!(
            state.apply(&update("example.uip", 1, 1)),
            Err(BlockchainError::UnknownDomain)
        );
    }

    #[test]
    fn update_wrong_owner_is_rejected() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();
        assert_eq!(
            state.apply(&update("example.uip", 2, 1)),
            Err(BlockchainError::NotOwner)
        );
        // State unchanged.
        let domain = state.domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.sequence, 0);
        assert_eq!(domain.record_hash, None);
    }

    #[test]
    fn update_requires_exactly_next_sequence() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();

        // Zero violates the core invariant (checked first).
        assert!(matches!(
            state.apply(&update("example.uip", 1, 0)),
            Err(BlockchainError::Core(_))
        ));

        for bad_sequence in [2u64, 3, u64::MAX] {
            assert_eq!(
                state.apply(&update("example.uip", 1, bad_sequence)),
                Err(BlockchainError::InvalidSequence {
                    expected: 1,
                    got: bad_sequence
                }),
                "sequence {bad_sequence}"
            );
        }
    }

    #[test]
    fn update_zero_sequence_fails_core_validation() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();
        assert!(matches!(
            state.apply(&update("example.uip", 1, 0)),
            Err(BlockchainError::Core(_))
        ));
    }

    #[test]
    fn register_then_update_then_update() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();
        state.apply(&update("example.uip", 1, 1)).unwrap();
        state.apply(&update("example.uip", 1, 2)).unwrap();

        let domain = state.domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.owner, owner(1));
        assert_eq!(domain.sequence, 2);
        assert_eq!(domain.record_hash, Some(RecordHash::from_bytes([2; 32])));
    }

    #[test]
    fn failed_apply_leaves_state_unchanged() {
        let mut state = ChainState::new();
        state.apply(&register("example.uip", 1)).unwrap();
        let snapshot = state.clone();

        let _ = state.apply(&register("example.uip", 9));
        let _ = state.apply(&update("example.uip", 9, 1));
        let _ = state.apply(&update("other.uip", 1, 1));
        let _ = state.apply(&update("example.uip", 1, 7));

        assert_eq!(state, snapshot);
    }

    #[test]
    fn same_transactions_same_final_state() {
        let txs = [
            register("a.uip", 1),
            register("b.uip", 2),
            update("a.uip", 1, 1),
            update("b.uip", 2, 1),
            update("a.uip", 1, 2),
        ];
        let mut left = ChainState::new();
        let mut right = ChainState::new();
        for tx in &txs {
            left.apply(tx).unwrap();
            right.apply(tx).unwrap();
        }
        assert_eq!(left, right);
        assert_eq!(left.len(), 2);
    }

    #[test]
    fn independent_domains_do_not_interfere() {
        let mut state = ChainState::new();
        state.apply(&register("a.uip", 1)).unwrap();
        state.apply(&register("b.uip", 2)).unwrap();
        state.apply(&update("b.uip", 2, 1)).unwrap();

        let a = state.domain(&domain_id("a.uip")).unwrap();
        assert_eq!((a.owner, a.sequence, a.record_hash), (owner(1), 0, None));
        let b = state.domain(&domain_id("b.uip")).unwrap();
        assert_eq!(b.sequence, 1);
    }
}
