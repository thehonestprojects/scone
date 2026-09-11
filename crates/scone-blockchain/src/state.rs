//! Canonical chain state and transaction application rules.

use std::collections::HashMap;

use scone_core::{DomainId, OwnerId, RecordHash, TldId, Transaction};

use crate::error::{BlockchainError, Result};

/// On-chain state of one registered domain.
///
/// Right after a `RegisterDomain`: `sequence == 0` and `record_hash == None`
/// (a registration claims the name; the first `UpdateDomain` publishes
/// records and sets `sequence` to 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainState {
    /// Current owner.
    pub owner: OwnerId,
    /// Latest applied `UpdateDomain` sequence (0 right after registration).
    pub sequence: u64,
    /// Current on-chain commitment to the DNS record set, once an
    /// `UpdateDomain` has been applied.
    pub record_hash: Option<RecordHash>,
}

/// On-chain state of one registered TLD (M7b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TldState {
    /// Current owner of the namespace.
    pub owner: OwnerId,
}

/// Authoritative in-memory state of a chain.
///
/// Direct `DomainId -> DomainState` access, no full scan (ready for
/// billions of domains; a storage backend will replace the map later,
/// the rules stay here). Domain names are never used as keys: the
/// 32-byte [`DomainId`] only. The TLD registry is a parallel
/// `TldId -> TldState` map (M7b), disjoint by id derivation.
///
/// Two nodes starting from the same state and applying exactly the same
/// blocks reach exactly equal [`ChainState`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainState {
    domains: HashMap<DomainId, DomainState>,
    tlds: HashMap<TldId, TldState>,
}

/// One reversible state change, as recorded by [`ChainState`]'s
/// undo log while a block is being applied.
///
/// Rollback replays the entries in **reverse** order, which restores
/// the exact pre-block state even when a block registers then
/// updates the same domain.
#[derive(Debug, Clone, Copy)]
enum UndoEntry {
    /// A `RegisterDomain` created the domain: rolling back removes it.
    RegisterDomain(DomainId),
    /// An `UpdateDomain` mutated the domain: rolling back restores `prior`.
    UpdateDomain {
        domain: DomainId,
        prior: DomainState,
    },
    /// A `RegisterTld` claimed the TLD: rolling back removes it.
    RegisterTld(TldId),
}

/// Revert journal of a block application (see
/// [`ChainState::apply_journaled`]).
///
/// Cost model: one entry per applied transaction (O(transactions per
/// block)), instead of cloning the whole domain map (O(domains)) per
/// block. Atomicity is identical: rollback restores the exact
/// pre-block state bit for bit, so two nodes applying the same blocks
/// still reach the same state (determinism preserved).
#[derive(Debug, Default)]
pub(crate) struct UndoLog {
    entries: Vec<UndoEntry>,
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

    /// Current state of `tld`, if registered (M7b TLD registry).
    #[must_use]
    pub fn tld(&self, tld: &TldId) -> Option<&TldState> {
        self.tlds.get(tld)
    }

    /// Number of registered TLDs.
    #[must_use]
    pub fn tld_len(&self) -> usize {
        self.tlds.len()
    }

    /// Whether no TLD is registered.
    #[must_use]
    pub fn tld_is_empty(&self) -> bool {
        self.tlds.is_empty()
    }

    /// Restores the persisted state of one domain (storage
    /// integration, see `scone-storage`). No rule is applied: the
    /// bytes were validated when the block was accepted; the decoded
    /// [`DomainState`] comes from the node's own store.
    ///
    /// Not journaled: this is a storage-load path, never part of a
    /// block application.
    ///
    /// # Errors
    ///
    /// Returns [`BlockchainError::DomainAlreadyRegistered`] if the
    /// domain is already restored (duplicate), which the caller treats
    /// as corrupted storage.
    pub fn restore_domain(&mut self, domain: DomainId, state: DomainState) -> Result<()> {
        if self.domains.contains_key(&domain) {
            return Err(BlockchainError::DomainAlreadyRegistered);
        }
        self.domains.insert(domain, state);
        Ok(())
    }

    /// Restores the persisted state of one TLD (storage
    /// integration). Same contract as [`ChainState::restore_domain`].
    ///
    /// # Errors
    ///
    /// Returns [`BlockchainError::TldAlreadyRegistered`] if the TLD is
    /// already restored (duplicate).
    pub fn restore_tld(&mut self, tld: TldId, state: TldState) -> Result<()> {
        if self.tlds.contains_key(&tld) {
            return Err(BlockchainError::TldAlreadyRegistered);
        }
        self.tlds.insert(tld, state);
        Ok(())
    }

    /// Applies `tx` to the state, deterministically and atomically (on
    /// error the state is left unchanged).
    ///
    /// Rules (see `/docs/technical/blockchain.md`):
    ///
    /// - **RegisterDomain**: the TLD of the carried name must be
    ///   registered (else [`BlockchainError::UnknownTld`] — D1, M7c)
    ///   and the domain must be free; it becomes
    ///   `{ owner, sequence: 0, record_hash: None }`. The proof is not
    ///   interpreted here — that is a consensus concern
    ///   (see [`crate::Consensus`]).
    /// - **UpdateDomain**: the domain must exist, `tx.owner` must be the
    ///   current owner, and `tx.sequence` must be exactly
    ///   `current + 1`; `record_hash` becomes the current commitment.
    /// - **RegisterTld**: the TLD must be free; it becomes
    ///   `{ owner }` (M7b).
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub fn apply(&mut self, tx: &Transaction) -> Result<()> {
        let mut journal = UndoLog::default();
        match self.apply_journaled(tx, &mut journal) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.rollback(journal);
                Err(e)
            }
        }
    }

    /// Applies `tx`, recording how to undo it in `journal` (no clone
    /// of the domain map). Block-level atomicity: the caller (see
    /// `Blockchain::push_block`) applies every transaction of a block
    /// into one shared [`UndoLog`] and calls [`ChainState::rollback`]
    /// with it if anything fails.
    ///
    /// On error the state is left unchanged **for this transaction**
    /// (nothing is journaled past the failing rule); rolling back the
    /// whole journal is the caller's job.
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub(crate) fn apply_journaled(
        &mut self,
        tx: &Transaction,
        journal: &mut UndoLog,
    ) -> Result<()> {
        tx.validate()?;
        match tx {
            Transaction::RegisterDomain(register) => {
                // D1 (M7c): the TLD namespace must already be claimed
                // on-chain — a `RegisterDomain` for `name.tld` requires
                // the TldId of `tld` in the registry, else
                // `UnknownTld`. The name is carried by the transaction
                // (M7b), so the chain derives the namespace id itself
                // (recompute, never trust a provided value).
                let tld_id = TldId::from_tld(&register.name.tld());
                if !self.tlds.contains_key(&tld_id) {
                    return Err(BlockchainError::UnknownTld);
                }
                if self.domains.contains_key(&register.domain_id) {
                    return Err(BlockchainError::DomainAlreadyRegistered);
                }
                let new_state = DomainState {
                    owner: register.owner,
                    sequence: 0,
                    record_hash: None,
                };
                self.domains.insert(register.domain_id, new_state);
                journal
                    .entries
                    .push(UndoEntry::RegisterDomain(register.domain_id));
            }
            Transaction::UpdateDomain(update) => {
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
                journal.entries.push(UndoEntry::UpdateDomain {
                    domain: update.domain_id,
                    prior: *state,
                });
                state.sequence = expected;
                state.record_hash = Some(update.record_hash);
            }
            Transaction::RegisterTld(register_tld) => {
                if self.tlds.contains_key(&register_tld.tld_id) {
                    return Err(BlockchainError::TldAlreadyRegistered);
                }
                self.tlds.insert(
                    register_tld.tld_id,
                    TldState {
                        owner: register_tld.owner,
                    },
                );
                journal
                    .entries
                    .push(UndoEntry::RegisterTld(register_tld.tld_id));
            }
        }
        Ok(())
    }

    /// Undoes every journaled change, most recent first, restoring
    /// the exact state captured before the journal started.
    pub(crate) fn rollback(&mut self, journal: UndoLog) {
        for entry in journal.entries.into_iter().rev() {
            match entry {
                UndoEntry::RegisterDomain(domain) => {
                    self.domains.remove(&domain);
                }
                UndoEntry::UpdateDomain { domain, prior } => {
                    self.domains.insert(domain, prior);
                }
                UndoEntry::RegisterTld(tld) => {
                    self.tlds.remove(&tld);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_core::{
        DomainName, Proof, RegisterDomain, RegisterTld, TldId, TldName, UpdateDomain,
    };
    use scone_crypto::{Signature, SigningKey};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    /// Note: these fixtures carry a placeholder signature; `apply`
    /// checks state rules and the owner/key binding, not the crypto
    /// (that is `validate_transaction`, exercised in `validate.rs`).
    fn register(name: &str, seed: u8) -> Transaction {
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).unwrap(),
            1,
            Proof::from_bytes(Vec::new()),
            key(seed).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn register_tld(tld: &str, seed: u8) -> Transaction {
        Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldId::from_tld(&TldName::new(tld).unwrap()),
            1,
            Proof::from_bytes(Vec::new()),
            key(seed).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn update(name: &str, seed: u8, sequence: u64) -> Transaction {
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            domain_id(name),
            sequence,
            RecordHash::from_bytes([sequence as u8; 32]),
            key(seed).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn owner(seed: u8) -> OwnerId {
        crate::validate::owner_from_public_key(&key(seed).public_key())
    }

    /// Registers the TLD `uip` (D1 prerequisite of every domain
    /// fixture below — M7c).
    fn seed_uip(state: &mut ChainState) {
        state.apply(&register_tld("uip", 1)).unwrap();
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
        seed_uip(&mut state);
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
        seed_uip(&mut state);
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
        seed_uip(&mut state);
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
        seed_uip(&mut state);
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
        seed_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        assert!(matches!(
            state.apply(&update("example.uip", 1, 0)),
            Err(BlockchainError::Core(_))
        ));
    }

    #[test]
    fn register_then_update_then_update() {
        let mut state = ChainState::new();
        seed_uip(&mut state);
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
        seed_uip(&mut state);
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
        seed_uip(&mut left);
        seed_uip(&mut right);
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
        seed_uip(&mut state);
        state.apply(&register("a.uip", 1)).unwrap();
        state.apply(&register("b.uip", 2)).unwrap();
        state.apply(&update("b.uip", 2, 1)).unwrap();

        let a = state.domain(&domain_id("a.uip")).unwrap();
        assert_eq!((a.owner, a.sequence, a.record_hash), (owner(1), 0, None));
        let b = state.domain(&domain_id("b.uip")).unwrap();
        assert_eq!(b.sequence, 1);
    }

    // --- RegisterTld (M7b) ---

    fn tld_id(tld: &str) -> TldId {
        TldId::from_tld(&TldName::new(tld).unwrap())
    }

    #[test]
    fn register_tld_creates_initial_tld_state() {
        let mut state = ChainState::new();
        assert!(state.tld_is_empty());
        state.apply(&register_tld("uip", 1)).unwrap();
        let tld = state.tld(&tld_id("uip")).unwrap();
        assert_eq!(tld.owner, owner(1));
        assert_eq!(state.tld_len(), 1);
    }

    #[test]
    fn double_register_tld_is_rejected() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        assert_eq!(
            state.apply(&register_tld("uip", 2)),
            Err(BlockchainError::TldAlreadyRegistered)
        );
        // Even by the same owner: the TLD is taken.
        assert_eq!(
            state.apply(&register_tld("uip", 1)),
            Err(BlockchainError::TldAlreadyRegistered)
        );
        assert_eq!(state.tld_len(), 1);
    }

    #[test]
    fn distinct_tlds_do_not_interfere() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        state.apply(&register_tld("com", 2)).unwrap();
        assert_eq!(state.tld_len(), 2);
        assert_eq!(state.tld(&tld_id("uip")).unwrap().owner, owner(1));
        assert_eq!(state.tld(&tld_id("com")).unwrap().owner, owner(2));
    }

    #[test]
    fn tld_registry_is_disjoint_from_domains() {
        // Registering the TLD "uip" never registers any domain, and
        // vice versa.
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        state.apply(&register("example.uip", 1)).unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(state.tld_len(), 1);
    }

    // --- D1: RegisterDomain requires its TLD on-chain (M7c) ---

    #[test]
    fn register_under_unknown_tld_is_rejected() {
        let mut state = ChainState::new();
        assert_eq!(
            state.apply(&register("example.uip", 1)),
            Err(BlockchainError::UnknownTld)
        );
        // Nothing was created, in either registry.
        assert_eq!(state.len(), 0);
        assert_eq!(state.tld_len(), 0);
    }

    #[test]
    fn register_under_registered_tld_is_accepted() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        state.apply(&register("example.uip", 2)).unwrap();
        // A second domain under the same TLD is fine (D2: allocation
        // under a TLD is open in v3).
        state.apply(&register("other.uip", 3)).unwrap();
        assert_eq!(state.len(), 2);
        assert_eq!(state.tld_len(), 1);
    }

    #[test]
    fn register_checks_the_tld_of_the_carried_name_not_the_owner() {
        // The TLD exists but was registered by a DIFFERENT key than
        // the domain registrant: still accepted (D2 — allocation
        // under a TLD is open, not gated by the TLD owner).
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        state.apply(&register("example.uip", 9)).unwrap();
        assert_eq!(
            state.domain(&domain_id("example.uip")).unwrap().owner,
            owner(9)
        );
    }

    #[test]
    fn another_registered_tld_does_not_help() {
        // Registering "com" does not open "uip": each namespace is
        // claimed independently.
        let mut state = ChainState::new();
        state.apply(&register_tld("com", 1)).unwrap();
        assert_eq!(
            state.apply(&register("example.uip", 1)),
            Err(BlockchainError::UnknownTld)
        );
    }

    #[test]
    fn unknown_tld_is_checked_before_domain_freedom() {
        // A double register under an unclaimed TLD reports
        // UnknownTld first: the namespace error dominates.
        let mut state = ChainState::new();
        state.apply(&register_tld("com", 1)).unwrap();
        state.apply(&register("example.com", 1)).unwrap();
        assert_eq!(
            state.apply(&register("example.uip", 1)),
            Err(BlockchainError::UnknownTld)
        );
    }
}
