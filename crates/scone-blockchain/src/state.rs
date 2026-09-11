//! Canonical chain state and transaction application rules (M8b).
//!
//! # SMT engagement (M6a)
//!
//! Besides the canonical direct-fold [`ChainState::state_root`]
//! (`SCONE-STATE-V2` — format frozen), the state carries an
//! **incremental sparse Merkle engagement** ([`crate::smt::Smt`]) of
//! its domain and TLD maps, maintained O(40 hashes) per journaled
//! mutation (apply / deterministic GC / rollback — see
//! [`ChainState::state_root_smt`]). Rollback replays the undo
//! entries in reverse order and re-inserts the exact prior leaf, so
//! the restored tree is **bit-identical** (physical shape and root),
//! never merely equivalent — a reorg that rewinds to the common
//! ancestor and replays a different branch converges to the exact
//! bytes every node computes for that branch.

use std::collections::{HashMap, HashSet};

use scone_core::id::{DOMAIN_ID_VERSION, TLD_ID_VERSION};
use scone_core::pow;
use scone_core::{DomainId, NetworkParams, OwnerId, RecordHash, TESTNET, TldId, Transaction};

use crate::error::{BlockchainError, Result};
use crate::smt::{Smt, smt_key};

/// Registration term of a domain: 1 year (M8b).
pub const DOMAIN_TERM_SECS: u64 = 365 * 24 * 3600;

/// Renewal grace period after expiry: 30 days (M8b). During grace the
/// domain is gone from the live state (resolution fails) but a fresh
/// `RegisterDomain` for the same name by a DIFFERENT owner is refused
/// until the period lapses, giving the original owner a re-register
/// window at the back of the queue.
pub const DOMAIN_GRACE_SECS: u64 = 30 * 24 * 3600;

/// Maximum registration horizon: 3 years ahead of the current block
/// time (M8b anti-hoarding bound; one renewal adds at most one term).
pub const DOMAIN_MAX_HORIZON_SECS: u64 = 3 * 365 * 24 * 3600;

/// On-chain state of one registered domain.
///
/// Right after a `RegisterDomain`/`AssignDomain`: `sequence == 0` and
/// `record_hash == None` (a registration claims the name; the first
/// `UpdateDomain` publishes records and sets `sequence` to 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainState {
    /// Current owner.
    pub owner: OwnerId,
    /// Latest applied `UpdateDomain` sequence (0 right after registration).
    pub sequence: u64,
    /// Current on-chain commitment to the DNS record set, once an
    /// `UpdateDomain` has been applied.
    pub record_hash: Option<RecordHash>,
    /// Block time at registration (Unix seconds, M8b).
    pub registered_at: u64,
    /// Registration expiry (Unix seconds, M8b). After this instant
    /// the domain stops resolving; after
    /// `valid_until + DOMAIN_GRACE_SECS` anyone may re-register it.
    pub valid_until: u64,
}

/// On-chain state of one registered TLD (M7b, extended M8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TldState {
    /// Current owner of the namespace.
    pub owner: OwnerId,
    /// `true` = anyone may register free domains under this TLD with
    /// `RegisterDomain` + PoW; `false` = assign-only (M8b). Defaults
    /// to `false` at `RegisterTld` time: a fresh namespace opens
    /// explicitly via `SetTldOpen`.
    pub open: bool,
}

impl TldState {
    /// State right after a `RegisterTld`: owned, closed (M8b).
    #[must_use]
    pub fn claimed_by(owner: OwnerId) -> Self {
        Self { owner, open: false }
    }
}

/// Authoritative in-memory state of a chain.
///
/// Direct `DomainId -> DomainState` access, no full scan (ready for
/// billions of domains; a storage backend will replace the map later,
/// the rules stay here). Domain names are never used as keys: the
/// 32-byte [`DomainId`] only. The TLD registry is a parallel
/// `TldId -> TldState` map (M7b), disjoint by id derivation.
///
/// Since M8b the state is bound to one network ([`NetworkParams`]):
/// every applied transaction must carry the same network id
/// (`WrongNetwork` otherwise), expirations are evaluated against the
/// block time supplied by the caller, and deterministic garbage
/// collection removes expired registrations.
///
/// Two nodes of the same network starting from the same state and
/// applying exactly the same blocks reach exactly equal
/// [`ChainState`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    network: NetworkParams,
    pub(crate) domains: HashMap<DomainId, DomainState>,
    pub(crate) tlds: HashMap<TldId, TldState>,
    /// OwnerId → signer public key (M3 of the .bak port): the PoS
    /// eligibility pool needs self-contained keys. Filled by apply
    /// (RegisterDomain carries the key of its owner; AssignDomain
    /// does NOT — the assignee's key becomes known at its first
    /// self-signed tx), replayed deterministically, never engaged in
    /// the state root (the owner-pool root hashes OwnerIds).
    pub(crate) owner_keys: HashMap<OwnerId, scone_crypto::PublicKey>,
    /// Names whose registration lapsed less than `DOMAIN_GRACE_SECS`
    /// ago: a re-register by anyone other than the previous owner is
    /// refused until grace elapses (keyed by the deterministic
    /// expiry instant, so replay/rollback stay exact).
    grace: HashMap<DomainId, (u64, OwnerId)>,
    /// Incremental SMT engagement of the domain and TLD maps (M6a):
    /// one tree, keyed by `smt_key(id)` (top 40 bits of the 32-byte
    /// id), leaf = the very same `SCONE-LEAF-DOM-V2` /
    /// `SCONE-LEAF-TLD-V2` encoding the canonical
    /// [`ChainState::state_root`] folds — the two commitments track
    /// the same logical state by construction. Maintained by every
    /// journaled mutation (apply/GC) and by `rollback` (bit-exact:
    /// the undo entries carry the prior leaf bytes), so a reorg
    /// replays without ever rebuilding the tree. DomainId and TldId
    /// are hashes with distinct derivation prefixes, hence uniformly
    /// distributed and disjoint in the 40-bit key space (collisions
    /// fall into the SMT's sorted buckets and remain deterministic).
    smt: Smt,
    /// Banned anchor keys (M9 slashing): proven checkpoint
    /// equivocators, removed from the PoS eligibility pool for life
    /// (a `SlashTx` ban is never lifted). Keyed by the raw public
    /// key: the ban follows the KEY, not the owner identity — a
    /// banned anchor cannot re-enter the pool by moving its domains
    /// around. Journaled (a reorg un-bans), engaged in the canonical
    /// state root and pruned-restored like every other state piece.
    pub(crate) banned: HashSet<scone_crypto::PublicKey>,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// One reversible state change, as recorded by [`ChainState`]'s
/// undo log while a block is being applied.
///
/// Rollback replays the entries in **reverse** order, which restores
/// the exact pre-block state even when a block registers then
/// updates the same domain.
#[derive(Debug, Clone, Copy)]
enum UndoEntry {
    /// A `RegisterDomain`/`AssignDomain` created the domain:
    /// rolling back removes it and restores the grace entry the
    /// registration consumed, if any.
    RegisterDomain {
        domain: DomainId,
        consumed_grace: Option<(u64, OwnerId)>,
    },
    /// An `UpdateDomain` mutated the domain: rolling back restores `prior`.
    UpdateDomain {
        domain: DomainId,
        prior: DomainState,
    },
    /// A `RegisterTld` claimed the TLD: rolling back removes it.
    RegisterTld(TldId),
    /// A TLD-owner operation mutated the TLD state: rolling back
    /// restores `prior` (M8b).
    MutateTld { tld: TldId, prior: TldState },
    /// A `RevokeTld` removed the TLD: rolling back restores `prior`.
    RevokeTld { tld: TldId, prior: TldState },
    /// A `RenewDomain` mutated the domain expiry: rolling back
    /// restores `prior` (M8b).
    RenewDomain {
        domain: DomainId,
        prior: DomainState,
    },
    /// A domain expired and was garbage-collected: rolling back
    /// restores it and drops the grace entry the GC created (M8b).
    ExpireDomain {
        domain: DomainId,
        prior: DomainState,
    },
    /// A self-signed tx taught the state an owner's public key
    /// (M3 of the .bak port): rolling back forgets it.
    LearnOwnerKey(OwnerId),
    /// A `SlashTx` banned the offender (M9): rolling back un-bans.
    /// The flag distinguishes "this tx inserted the ban" from
    /// "the key was already banned" (idempotent re-slash: nothing
    /// journaled, nothing undone).
    BanAnchor {
        /// The banned key.
        offender: scone_crypto::PublicKey,
    },
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
    /// Empty state for the **testnet** (development default).
    #[must_use]
    pub fn new() -> Self {
        Self::for_network(TESTNET)
    }

    /// Empty state for an explicit network (M8b).
    #[must_use]
    pub fn for_network(network: NetworkParams) -> Self {
        Self {
            network,
            domains: HashMap::new(),
            tlds: HashMap::new(),
            owner_keys: HashMap::new(),
            grace: HashMap::new(),
            smt: Smt::new(),
            banned: HashSet::new(),
        }
    }

    /// The network this state belongs to (M8b).
    #[must_use]
    pub fn network(&self) -> NetworkParams {
        self.network
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

    /// Current state of `domain`, if registered and not expired at
    /// `now` (the caller supplies the deterministic block time).
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

    /// Whether `key` is banned from the PoS eligibility pool (M9
    /// slashing: proven checkpoint equivocation, lifetime ban).
    #[must_use]
    pub fn is_banned(&self, key: &scone_crypto::PublicKey) -> bool {
        self.banned.contains(key)
    }

    // ——— SMT engagement (M6a) ———

    /// SMT leaf of a registered domain — the exact
    /// `SCONE-LEAF-DOM-V2` bytes the canonical `state_root` folds
    /// (see [`crate::finality::domain_leaf_v2`]).
    fn smt_domain_leaf(id: &DomainId, st: &crate::state::DomainState) -> [u8; 32] {
        crate::finality::domain_leaf_v2(id, st)
    }

    /// SMT leaf of a registered TLD (see
    /// [`crate::finality::tld_leaf_v2`]).
    fn smt_tld_leaf(id: &TldId, st: &crate::state::TldState) -> [u8; 32] {
        crate::finality::tld_leaf_v2(id, st)
    }

    /// Writes a domain leaf into the SMT (replacement = remove of
    /// the exact old leaf + insert of the new one, both O(40)
    /// hashes). `old` avoids a redundant remove for fresh inserts.
    fn smt_put_domain(
        &mut self,
        id: &DomainId,
        old: Option<&crate::state::DomainState>,
        new: &crate::state::DomainState,
    ) {
        let key = smt_key(id.as_bytes());
        if let Some(prior) = old {
            self.smt.remove(key, &Self::smt_domain_leaf(id, prior));
        }
        self.smt.insert(key, Self::smt_domain_leaf(id, new));
    }

    /// Removes a domain leaf from the SMT.
    fn smt_remove_domain(&mut self, id: &DomainId, st: &crate::state::DomainState) {
        self.smt
            .remove(smt_key(id.as_bytes()), &Self::smt_domain_leaf(id, st));
    }

    /// Writes a TLD leaf into the SMT (replacement path).
    fn smt_put_tld(
        &mut self,
        id: &TldId,
        old: &crate::state::TldState,
        new: &crate::state::TldState,
    ) {
        let key = smt_key(id.as_bytes());
        self.smt.remove(key, &Self::smt_tld_leaf(id, old));
        self.smt.insert(key, Self::smt_tld_leaf(id, new));
    }

    /// Inserts a TLD leaf into the SMT (fresh claim).
    fn smt_insert_tld(&mut self, id: &TldId, st: &crate::state::TldState) {
        self.smt
            .insert(smt_key(id.as_bytes()), Self::smt_tld_leaf(id, st));
    }

    /// Removes a TLD leaf from the SMT.
    fn smt_remove_tld(&mut self, id: &TldId, st: &crate::state::TldState) {
        self.smt
            .remove(smt_key(id.as_bytes()), &Self::smt_tld_leaf(id, st));
    }

    /// Incremental SMT state root (M6a): `blake3("SCONE-STATE-SMT-V1"
    /// || smt_root)` over the domain+TLD tree maintained by every
    /// journaled mutation. O(1) — the tree root is cached.
    ///
    /// Choice (documented, per M6a): this is an **incremental
    /// engagement**, not the canonical one. The canonical commitment
    /// of the current protocol version remains the direct-fold
    /// [`ChainState::state_root`] (`SCONE-STATE-V2`, format frozen) —
    /// `state_root_smt` never feeds consensus artifacts. The two
    /// commit the same leaves, so equality of logical states implies
    /// equality of BOTH roots; the SMT additionally provides
    /// O(40)-per-tx maintenance and non-membership-capable proofs at
    /// O(log N), which the flat V2 fold cannot.
    #[must_use]
    pub fn state_root_smt(&self) -> [u8; 32] {
        let mut top = Vec::with_capacity(18 + 32);
        top.extend_from_slice(b"SCONE-STATE-SMT-V1");
        top.extend_from_slice(&self.smt.root());
        scone_crypto::hash256(&[&top])
    }

    /// The incremental SMT itself (diagnostics/tests).
    #[must_use]
    pub fn smt(&self) -> &Smt {
        &self.smt
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
        self.smt_put_domain(&domain, None, &state);
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
        self.smt_insert_tld(&tld, &state);
        self.tlds.insert(tld, state);
        Ok(())
    }

    /// Applies `tx` to the state, deterministically and atomically (on
    /// error the state is left unchanged).
    ///
    /// Uses a zero block time (no GC, no time-based rule): the
    /// block-level path is [`ChainState::apply_journaled_at`].
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub fn apply(&mut self, tx: &Transaction) -> Result<()> {
        let mut journal = UndoLog::default();
        match self.apply_journaled_at(tx, 0, &mut journal) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.rollback(journal);
                Err(e)
            }
        }
    }

    /// Applies `tx` at block time `now`, recording how to undo it in
    /// `journal` (no clone of the domain map). Block-level atomicity:
    /// the caller (see `Blockchain::push_block`) applies every
    /// transaction of a block into one shared [`UndoLog`] and calls
    /// [`ChainState::rollback`] with it if anything fails.
    ///
    /// `now` is the **parent block timestamp** (deterministic: it is
    /// committed in the parent header, unlike the wall clock).
    ///
    /// On error the state is left unchanged **for this transaction**
    /// (nothing is journaled past the failing rule); rolling back the
    /// whole journal is the caller's job.
    ///
    /// Rules (M8b — see `/docs/technical/blockchain.md`):
    ///
    /// - every transaction must carry this chain's network id
    ///   (`WrongNetwork` otherwise);
    /// - **RegisterTld**: TLD free, PoW at the network's TLD
    ///   difficulty over `"SCONE-TLD-V1" || tld`; new state
    ///   `{ owner, open: false }`;
    /// - **RegisterDomain**: TLD registered (D1) AND open
    ///   (`TldClosed` otherwise), domain free (respecting the grace
    ///   window of a lapsed registration), PoW at the network's
    ///   domain difficulty; `valid_until = now + 1 year`;
    /// - **UpdateDomain**: domain exists and unexpired, owner, exact
    ///   next sequence;
    /// - **TransferTld / RevokeTld / SetTldOpen**: TLD exists, signer
    ///   is the current owner;
    /// - **AssignDomain**: TLD of the name exists, signer owns it,
    ///   domain free; `assignee` becomes the owner (no PoW — the
    ///   namespace owner vouches);
    /// - **RenewDomain**: domain exists, owner, `valid_until`
    ///   strictly extends the current expiry and stays within
    ///   `now + 3 years`.
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub(crate) fn apply_journaled_at(
        &mut self,
        tx: &Transaction,
        now: u64,
        journal: &mut UndoLog,
    ) -> Result<()> {
        tx.validate()?;
        // M8b network separation: a tx of another network never
        // applies, whatever its other merits.
        if tx.network() != self.network.network_id {
            return Err(BlockchainError::WrongNetwork {
                tx: tx.network(),
                chain: self.network.network_id,
            });
        }
        match tx {
            Transaction::RegisterDomain(register) => {
                let tld_id = TldId::from_tld(&register.name.tld());
                let tld = self.tlds.get(&tld_id).ok_or(BlockchainError::UnknownTld)?;
                if !tld.open {
                    return Err(BlockchainError::TldClosed);
                }
                self.ensure_domain_free(&register.domain_id, now, &register.owner)?;
                // PoW over the domain derivation input, recomputed
                // from the carried name — never from a provided hash.
                let mut challenge =
                    Vec::with_capacity(DOMAIN_ID_VERSION.len() + register.name.canonical().len());
                challenge.extend_from_slice(DOMAIN_ID_VERSION);
                challenge.extend_from_slice(register.name.canonical().as_bytes());
                pow::verify(
                    self.network.network_id,
                    &challenge,
                    register.proof.as_bytes(),
                    self.network.domain_pow_difficulty,
                )?;
                let valid_until = now + DOMAIN_TERM_SECS;
                // M3 (.bak port): learn the owner's self-contained
                // key (PoS pool resolution). RegisterDomain is
                // self-signed — first appearance wins, replay-safe.
                // Journaled: a rolled-back block un-learns it.
                if let std::collections::hash_map::Entry::Vacant(v) =
                    self.owner_keys.entry(register.owner)
                {
                    v.insert(register.public_key);
                    journal
                        .entries
                        .push(UndoEntry::LearnOwnerKey(register.owner));
                }
                // A lapsed registration being re-registered within
                // grace (previous owner only — checked by
                // `ensure_domain_free`): the grace entry is consumed.
                let consumed_grace = self.grace.remove(&register.domain_id);
                let new_state = DomainState {
                    owner: register.owner,
                    sequence: 0,
                    record_hash: None,
                    registered_at: now,
                    valid_until,
                };
                self.smt_put_domain(&register.domain_id, None, &new_state);
                self.domains.insert(register.domain_id, new_state);
                journal.entries.push(UndoEntry::RegisterDomain {
                    domain: register.domain_id,
                    consumed_grace,
                });
            }
            Transaction::UpdateDomain(update) => {
                let state = self
                    .domains
                    .get_mut(&update.domain_id)
                    .ok_or(BlockchainError::UnknownDomain)?;
                if state.owner != update.owner {
                    return Err(BlockchainError::NotOwner);
                }
                // M3 (.bak port): learn the owner's key — self-signed
                // tx, first appearance wins, replay-safe. AFTER the
                // owner check: a rejected tx must not mutate anything.
                if let std::collections::hash_map::Entry::Vacant(v) =
                    self.owner_keys.entry(update.owner)
                {
                    v.insert(update.public_key);
                    journal.entries.push(UndoEntry::LearnOwnerKey(update.owner));
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
                // Copy the prior state out so the `get_mut` borrow of
                // `self.domains` ends before the SMT update takes
                // `&mut self`.
                let (id, prior_state) = (update.domain_id, *state);
                let mut next = prior_state;
                next.sequence = expected;
                next.record_hash = Some(update.record_hash);
                journal.entries.push(UndoEntry::UpdateDomain {
                    domain: id,
                    prior: prior_state,
                });
                self.smt_put_domain(&id, Some(&prior_state), &next);
                self.domains.insert(id, next);
            }
            Transaction::RegisterTld(register_tld) => {
                if self.tlds.contains_key(&register_tld.tld_id) {
                    return Err(BlockchainError::TldAlreadyRegistered);
                }
                // PoW over the TLD derivation input, recomputed from
                // the carried name.
                let mut challenge =
                    Vec::with_capacity(TLD_ID_VERSION.len() + register_tld.name.as_str().len());
                challenge.extend_from_slice(TLD_ID_VERSION);
                challenge.extend_from_slice(register_tld.name.as_str().as_bytes());
                pow::verify(
                    self.network.network_id,
                    &challenge,
                    register_tld.proof.as_bytes(),
                    self.network.tld_pow_difficulty,
                )?;
                // M5: learn the TLD owner's key — the TLD owner is a
                // PoS stakeholder (the claim cost a PoW). Journaled:
                // a rolled-back block un-learns it.
                if let std::collections::hash_map::Entry::Vacant(v) =
                    self.owner_keys.entry(register_tld.owner)
                {
                    v.insert(register_tld.public_key);
                    journal
                        .entries
                        .push(UndoEntry::LearnOwnerKey(register_tld.owner));
                }
                let new_tld = TldState {
                    owner: register_tld.owner,
                    open: false,
                };
                self.smt_insert_tld(&register_tld.tld_id, &new_tld);
                self.tlds.insert(register_tld.tld_id, new_tld);
                journal
                    .entries
                    .push(UndoEntry::RegisterTld(register_tld.tld_id));
            }
            Transaction::TransferTld(transfer) => {
                let state = self
                    .tlds
                    .get_mut(&transfer.tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if state.owner != transfer.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                // Copy out so the `get_mut` borrow ends before the
                // SMT update takes `&mut self`.
                let (tld, prior) = (transfer.tld_id, *state);
                let mut next = prior;
                next.owner = transfer.new_owner;
                journal.entries.push(UndoEntry::MutateTld { tld, prior });
                self.smt_put_tld(&tld, &prior, &next);
                self.tlds.insert(tld, next);
            }
            Transaction::RevokeTld(revoke) => {
                let state = self
                    .tlds
                    .get_mut(&revoke.tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if state.owner != revoke.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                let prior = *state;
                self.smt_remove_tld(&revoke.tld_id, &prior);
                self.tlds.remove(&revoke.tld_id);
                journal.entries.push(UndoEntry::RevokeTld {
                    tld: revoke.tld_id,
                    prior,
                });
            }
            Transaction::SetTldOpen(set_open) => {
                let state = self
                    .tlds
                    .get_mut(&set_open.tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if state.owner != set_open.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                let (tld, prior) = (set_open.tld_id, *state);
                let mut next = prior;
                next.open = set_open.open;
                journal.entries.push(UndoEntry::MutateTld { tld, prior });
                self.smt_put_tld(&tld, &prior, &next);
                self.tlds.insert(tld, next);
            }
            Transaction::AssignDomain(assign) => {
                let tld_id = TldId::from_tld(&assign.name.tld());
                let tld = self.tlds.get(&tld_id).ok_or(BlockchainError::UnknownTld)?;
                if tld.owner != assign.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                // The grace window follows the DOMAIN, not the
                // assigner: only the lapsed owner re-registers during
                // grace (via RegisterDomain or an assignment to
                // themselves).
                self.ensure_domain_free(&assign.domain_id, now, &assign.assignee)?;
                let consumed_grace = self.grace.remove(&assign.domain_id);
                let new_state = DomainState {
                    owner: assign.assignee,
                    sequence: 0,
                    record_hash: None,
                    registered_at: now,
                    valid_until: now + DOMAIN_TERM_SECS,
                };
                self.smt_put_domain(&assign.domain_id, None, &new_state);
                self.domains.insert(assign.domain_id, new_state);
                journal.entries.push(UndoEntry::RegisterDomain {
                    domain: assign.domain_id,
                    consumed_grace,
                });
            }
            Transaction::RenewDomain(renew) => {
                let state = self
                    .domains
                    .get_mut(&renew.domain_id)
                    .ok_or(BlockchainError::UnknownDomain)?;
                if state.owner != renew.owner {
                    return Err(BlockchainError::NotOwner);
                }
                if renew.valid_until <= state.valid_until {
                    return Err(BlockchainError::RenewalNotExtending {
                        current: state.valid_until,
                        proposed: renew.valid_until,
                    });
                }
                let max = now.saturating_add(DOMAIN_MAX_HORIZON_SECS);
                if renew.valid_until > max {
                    return Err(BlockchainError::RenewalExceedsTerm {
                        max,
                        proposed: renew.valid_until,
                    });
                }
                let (domain, prior) = (renew.domain_id, *state);
                let mut next = prior;
                next.valid_until = renew.valid_until;
                journal
                    .entries
                    .push(UndoEntry::RenewDomain { domain, prior });
                self.smt_put_domain(&domain, Some(&prior), &next);
                self.domains.insert(domain, next);
            }
            Transaction::Slash(slash) => {
                // M9 — equivocation evidence. The cryptographic proof
                // was already re-verified by `tx.validate()` above
                // (defence in depth: same pure check runs at
                // encode/decode/validate). Two state rules remain:
                //
                // 1. the offender must be in the eligibility pool AT
                //    APPLICATION TIME — the pool of the current state
                //    (live-domain/TLD owners, the same snapshot
                //    `eligible_validators` computes). The committee of
                //    the evidence's epoch is NOT reconstructible from
                //    a bare ChainState (it depends on the finalized
                //    checkpoint history), so the check is anchored to
                //    the live pool: an equivocator loses their stake
                //    seat by definition, and a key that already left
                //    the pool (expired domains) has nothing left to
                //    ban — documented limitation, cf. .bak §9.
                // 2. BAN: the offender's key leaves the pool for life
                //    (idempotent — an already-banned key changes
                //    nothing, the tx is still valid and its evidence
                //    permanent). The offender's DOMAINS and TLDs are
                //    deliberately NOT seized: the minimal sanction is
                //    the loss of the anchor seat, not the property
                //    (documented decision — the domains keep
                //    resolving and renewing; only the PoS privileges
                //    die).
                let pool = self.eligible_validators(now);
                if !pool.contains(&slash.offender) {
                    return Err(BlockchainError::SlashOffenderNotInPool);
                }
                if self.banned.insert(slash.offender) {
                    journal.entries.push(UndoEntry::BanAnchor {
                        offender: slash.offender,
                    });
                }
            }
        }
        Ok(())
    }

    /// Domain-freedom check shared by `RegisterDomain` and
    /// `AssignDomain`: not currently registered (M7 rule) and not in
    /// a grace window owned by someone else (M8b rule).
    fn ensure_domain_free(&self, domain: &DomainId, now: u64, claimant: &OwnerId) -> Result<()> {
        if self.domains.contains_key(domain) {
            return Err(BlockchainError::DomainAlreadyRegistered);
        }
        if let Some(&(expired_at, lapsed_owner)) = self.grace.get(domain)
            && now < expired_at.saturating_add(DOMAIN_GRACE_SECS)
            && *claimant != lapsed_owner
        {
            // Frozen for everyone but the previous owner until
            // expiry + grace.
            return Err(BlockchainError::DomainAlreadyRegistered);
        }
        Ok(())
    }

    /// Deterministic garbage collection of expired registrations
    /// (M8b). Removes every domain whose `valid_until < now` from the
    /// live registry and parks it in the grace map. Called by
    /// `Blockchain::push_block` with the **parent** block timestamp
    /// before applying the block's transactions — same blocks, same
    /// time input, same result on every node.
    ///
    /// Journaled: a rolled-back block restores the exact pre-GC
    /// registry bit for bit.
    pub(crate) fn gc_expired_journaled(
        &mut self,
        now: u64,
        journal: &mut UndoLog,
    ) -> Vec<DomainId> {
        let expired: Vec<DomainId> = self
            .domains
            .iter()
            .filter(|(_, state)| state.valid_until <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired.clone() {
            let prior = self.domains.remove(&id).expect("checked present");
            self.smt_remove_domain(&id, &prior);
            self.grace.insert(id, (prior.valid_until, prior.owner));
            journal
                .entries
                .push(UndoEntry::ExpireDomain { domain: id, prior });
        }
        expired
    }

    /// Undoes every journaled change, most recent first, restoring
    /// the exact state captured before the journal started —
    /// **including the SMT engagement** (M6a): each entry replays
    /// the exact inverse leaf operation (re-insert the prior leaf /
    /// remove the inserted leaf), so the restored tree is
    /// bit-identical (physical shape and root) to the pre-journal
    /// tree, not merely an equivalent commitment.
    pub(crate) fn rollback(&mut self, journal: UndoLog) {
        for entry in journal.entries.into_iter().rev() {
            match entry {
                UndoEntry::RegisterDomain {
                    domain,
                    consumed_grace,
                } => {
                    if let Some(state) = self.domains.remove(&domain) {
                        self.smt_remove_domain(&domain, &state);
                    }
                    if let Some(entry) = consumed_grace {
                        self.grace.insert(domain, entry);
                    }
                }
                UndoEntry::UpdateDomain { domain, prior } => {
                    if let Some(current) = self.domains.insert(domain, prior) {
                        self.smt_put_domain(&domain, Some(&current), &prior);
                    }
                }
                UndoEntry::RegisterTld(tld) => {
                    if let Some(state) = self.tlds.remove(&tld) {
                        self.smt_remove_tld(&tld, &state);
                    }
                }
                UndoEntry::MutateTld { tld, prior } => {
                    if let Some(current) = self.tlds.insert(tld, prior) {
                        self.smt_put_tld(&tld, &current, &prior);
                    }
                }
                UndoEntry::RevokeTld { tld, prior } => {
                    self.smt_insert_tld(&tld, &prior);
                    self.tlds.insert(tld, prior);
                }
                UndoEntry::RenewDomain { domain, prior } => {
                    if let Some(current) = self.domains.insert(domain, prior) {
                        self.smt_put_domain(&domain, Some(&current), &prior);
                    }
                }
                UndoEntry::ExpireDomain { domain, prior } => {
                    self.grace.remove(&domain);
                    self.smt_put_domain(&domain, None, &prior);
                    self.domains.insert(domain, prior);
                }
                UndoEntry::LearnOwnerKey(owner) => {
                    self.owner_keys.remove(&owner);
                }
                UndoEntry::BanAnchor { offender } => {
                    self.banned.remove(&offender);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_core::{
        AssignDomain, DomainName, Proof, RegisterDomain, RegisterTld, RenewDomain, RevokeTld,
        SetTldOpen, TldName, TransferTld, UpdateDomain,
    };
    use scone_crypto::{Signature, SigningKey};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    /// Mines a valid registration proof for `challenge` at the
    /// testnet difficulty of `kind` ("tld" or "domain").
    fn mined_proof(challenge: &[u8], kind: &str) -> Proof {
        let difficulty = match kind {
            "tld" => TESTNET.tld_pow_difficulty,
            _ => TESTNET.domain_pow_difficulty,
        };
        let checked = pow::mine(TESTNET.network_id, challenge, difficulty);
        Proof::from_bytes(pow::encode_proof(&checked))
    }

    fn tld_challenge(tld: &str) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(TLD_ID_VERSION);
        c.extend_from_slice(tld.as_bytes());
        c
    }

    fn domain_challenge(name: &str) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(DOMAIN_ID_VERSION);
        c.extend_from_slice(name.as_bytes());
        c
    }

    fn register(name: &str, seed: u8) -> Transaction {
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).unwrap(),
            1,
            mined_proof(&domain_challenge(name), "domain"),
            key(seed).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn register_tld(tld: &str, seed: u8) -> Transaction {
        Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldName::new(tld).unwrap(),
            1,
            mined_proof(&tld_challenge(tld), "tld"),
            key(seed).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn set_open(tld: &str, seed: u8, open: bool) -> Transaction {
        Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
            TldId::from_tld(&TldName::new(tld).unwrap()),
            open,
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

    fn renew(name: &str, seed: u8, valid_until: u64) -> Transaction {
        Transaction::RenewDomain(RenewDomain::renew_domain_signed(
            domain_id(name),
            valid_until,
            key(seed).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn owner(seed: u8) -> OwnerId {
        crate::validate::owner_from_public_key(&key(seed).public_key())
    }

    /// Claims `uip` (PoW), opens it, and returns the state ready for
    /// domain fixtures.
    fn seed_open_uip(state: &mut ChainState) {
        state.apply(&register_tld("uip", 1)).unwrap();
        state.apply(&set_open("uip", 1, true)).unwrap();
    }

    fn tld_id(tld: &str) -> TldId {
        TldId::from_tld(&TldName::new(tld).unwrap())
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
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        let domain = state.domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.owner, owner(1));
        assert_eq!(domain.sequence, 0);
        assert_eq!(domain.record_hash, None);
        assert_eq!(domain.valid_until, DOMAIN_TERM_SECS);
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn double_register_is_rejected() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
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
        seed_open_uip(&mut state);
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
        seed_open_uip(&mut state);
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
    fn register_then_update_then_update() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
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
        seed_open_uip(&mut state);
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
        seed_open_uip(&mut left);
        seed_open_uip(&mut right);
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
        seed_open_uip(&mut state);
        state.apply(&register("a.uip", 1)).unwrap();
        state.apply(&register("b.uip", 2)).unwrap();
        state.apply(&update("b.uip", 2, 1)).unwrap();

        let a = state.domain(&domain_id("a.uip")).unwrap();
        assert_eq!((a.owner, a.sequence, a.record_hash), (owner(1), 0, None));
        let b = state.domain(&domain_id("b.uip")).unwrap();
        assert_eq!(b.sequence, 1);
    }

    // --- RegisterTld (M7b) + PoW (M8b) ---

    #[test]
    fn register_tld_creates_initial_tld_state() {
        let mut state = ChainState::new();
        assert!(state.tld_is_empty());
        state.apply(&register_tld("uip", 1)).unwrap();
        let tld = state.tld(&tld_id("uip")).unwrap();
        assert_eq!(tld.owner, owner(1));
        // M8b: a fresh namespace is closed.
        assert!(!tld.open);
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
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        assert_eq!(state.len(), 1);
        assert_eq!(state.tld_len(), 1);
    }

    #[test]
    fn register_tld_without_pow_is_rejected() {
        let mut state = ChainState::new();
        let tx = Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldName::new("uip").unwrap(),
            1,
            Proof::from_bytes(Vec::new()),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert!(matches!(state.apply(&tx), Err(BlockchainError::Core(_))));
        assert!(state.tld_is_empty());
    }

    #[test]
    fn register_tld_with_wrong_challenge_pow_is_rejected() {
        // A proof mined for TLD "com" does not claim "uip".
        let mut state = ChainState::new();
        let tx = Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldName::new("uip").unwrap(),
            1,
            mined_proof(&tld_challenge("com"), "tld"),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert!(matches!(state.apply(&tx), Err(BlockchainError::Core(_))));
    }

    #[test]
    fn register_domain_without_pow_is_rejected() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        let tx = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new("example.uip").unwrap(),
            1,
            Proof::from_bytes(Vec::new()),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert!(matches!(state.apply(&tx), Err(BlockchainError::Core(_))));
        assert_eq!(state.len(), 0);
    }

    // --- D1: RegisterDomain requires its TLD on-chain (M7c) ---

    #[test]
    fn register_under_unknown_tld_is_rejected() {
        let mut state = ChainState::new();
        assert_eq!(
            state.apply(&register("example.uip", 1)),
            Err(BlockchainError::UnknownTld)
        );
        assert_eq!(state.len(), 0);
        assert_eq!(state.tld_len(), 0);
    }

    #[test]
    fn register_under_closed_tld_is_rejected() {
        // M8b: claimed but NOT opened ⇒ assign-only.
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        assert_eq!(
            state.apply(&register("example.uip", 2)),
            Err(BlockchainError::TldClosed)
        );
    }

    #[test]
    fn register_under_open_tld_is_accepted() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 2)).unwrap();
        state.apply(&register("other.uip", 3)).unwrap();
        assert_eq!(state.len(), 2);
        assert_eq!(state.tld_len(), 1);
    }

    #[test]
    fn another_registered_tld_does_not_help() {
        let mut state = ChainState::new();
        state.apply(&register_tld("com", 1)).unwrap();
        state.apply(&set_open("com", 1, true)).unwrap();
        assert_eq!(
            state.apply(&register("example.uip", 1)),
            Err(BlockchainError::UnknownTld)
        );
    }

    // --- SetTldOpen (M8b) ---

    #[test]
    fn set_open_requires_the_tld_owner() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        assert_eq!(
            state.apply(&set_open("uip", 2, true)),
            Err(BlockchainError::NotTldOwner)
        );
        assert!(!state.tld(&tld_id("uip")).unwrap().open);
        state.apply(&set_open("uip", 1, true)).unwrap();
        assert!(state.tld(&tld_id("uip")).unwrap().open);
        // Closing back works too.
        state.apply(&set_open("uip", 1, false)).unwrap();
        assert!(!state.tld(&tld_id("uip")).unwrap().open);
    }

    #[test]
    fn set_open_on_unknown_tld_is_rejected() {
        let mut state = ChainState::new();
        assert_eq!(
            state.apply(&set_open("uip", 1, true)),
            Err(BlockchainError::UnknownTld)
        );
    }

    // --- TransferTld (M8b) ---

    #[test]
    fn transfer_moves_ownership() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        let tx = Transaction::TransferTld(TransferTld::transfer_tld_signed(
            tld_id("uip"),
            owner(2),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&tx).unwrap();
        assert_eq!(state.tld(&tld_id("uip")).unwrap().owner, owner(2));
        // The old owner cannot administer the namespace anymore.
        assert_eq!(
            state.apply(&set_open("uip", 1, true)),
            Err(BlockchainError::NotTldOwner)
        );
        // The new owner can.
        state.apply(&set_open("uip", 2, true)).unwrap();
        assert!(state.tld(&tld_id("uip")).unwrap().open);
    }

    #[test]
    fn transfer_by_non_owner_and_unknown_tld_are_rejected() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        let stranger = Transaction::TransferTld(TransferTld::transfer_tld_signed(
            tld_id("uip"),
            owner(2),
            key(9).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_eq!(state.apply(&stranger), Err(BlockchainError::NotTldOwner));
        let ghost = Transaction::TransferTld(TransferTld::transfer_tld_signed(
            tld_id("zzz"),
            owner(2),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_eq!(state.apply(&ghost), Err(BlockchainError::UnknownTld));
    }

    // --- RevokeTld (M8b) ---

    #[test]
    fn revoke_frees_the_namespace() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        let tx = Transaction::RevokeTld(RevokeTld::revoke_tld_signed(
            tld_id("uip"),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&tx).unwrap();
        assert!(state.tld(&tld_id("uip")).is_none());
        // Re-claimable by anyone with a fresh PoW.
        state.apply(&register_tld("uip", 2)).unwrap();
        assert_eq!(state.tld(&tld_id("uip")).unwrap().owner, owner(2));
    }

    #[test]
    fn revoke_by_non_owner_is_rejected() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        let tx = Transaction::RevokeTld(RevokeTld::revoke_tld_signed(
            tld_id("uip"),
            key(9).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_eq!(state.apply(&tx), Err(BlockchainError::NotTldOwner));
    }

    // --- AssignDomain (M8b) ---

    #[test]
    fn assign_creates_the_domain_for_the_assignee() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap(); // closed
        let tx = Transaction::AssignDomain(AssignDomain::assign_domain_signed(
            DomainName::new("assigned.uip").unwrap(),
            owner(5),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&tx).unwrap();
        let domain = state.domain(&domain_id("assigned.uip")).unwrap();
        assert_eq!(domain.owner, owner(5));
        assert_eq!(domain.sequence, 0);
    }

    #[test]
    fn assign_by_non_tld_owner_is_rejected() {
        let mut state = ChainState::new();
        state.apply(&register_tld("uip", 1)).unwrap();
        let tx = Transaction::AssignDomain(AssignDomain::assign_domain_signed(
            DomainName::new("assigned.uip").unwrap(),
            owner(5),
            key(9).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_eq!(state.apply(&tx), Err(BlockchainError::NotTldOwner));
    }

    #[test]
    fn assign_works_on_an_open_tld_too() {
        // Open does not forbid assignment (the owner may still vouch).
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        let tx = Transaction::AssignDomain(AssignDomain::assign_domain_signed(
            DomainName::new("assigned.uip").unwrap(),
            owner(5),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&tx).unwrap();
        assert_eq!(
            state.domain(&domain_id("assigned.uip")).unwrap().owner,
            owner(5)
        );
    }

    #[test]
    fn assign_on_unknown_tld_is_rejected() {
        let mut state = ChainState::new();
        let tx = Transaction::AssignDomain(AssignDomain::assign_domain_signed(
            DomainName::new("assigned.uip").unwrap(),
            owner(5),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_eq!(state.apply(&tx), Err(BlockchainError::UnknownTld));
    }

    // --- RenewDomain (M8b) ---

    #[test]
    fn renew_extends_the_expiry() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        let before = state.domain(&domain_id("example.uip")).unwrap().valid_until;
        // now = 0 in `apply`, current expiry = TERM; renew to TERM+1h.
        let target = DOMAIN_TERM_SECS + 3600;
        state.apply(&renew("example.uip", 1, target)).unwrap();
        assert_eq!(
            state.domain(&domain_id("example.uip")).unwrap().valid_until,
            target
        );
        assert!(target > before);
    }

    #[test]
    fn renew_must_strictly_extend() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        let current = state.domain(&domain_id("example.uip")).unwrap().valid_until;
        for bad in [current - 1, current] {
            assert_eq!(
                state.apply(&renew("example.uip", 1, bad)),
                Err(BlockchainError::RenewalNotExtending {
                    current,
                    proposed: bad
                })
            );
        }
    }

    #[test]
    fn renew_is_capped_at_three_years_ahead() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        // `apply` uses now=0: horizon = 3 years.
        let max = DOMAIN_MAX_HORIZON_SECS;
        assert_eq!(
            state.apply(&renew("example.uip", 1, max + 1)),
            Err(BlockchainError::RenewalExceedsTerm {
                max,
                proposed: max + 1
            })
        );
        // Exactly the horizon is fine.
        state.apply(&renew("example.uip", 1, max)).unwrap();
    }

    #[test]
    fn renew_by_non_owner_and_unknown_domain_are_rejected() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        assert_eq!(
            state.apply(&renew("example.uip", 9, DOMAIN_TERM_SECS + 99)),
            Err(BlockchainError::NotOwner)
        );
        assert_eq!(
            state.apply(&renew("other.uip", 1, DOMAIN_TERM_SECS + 99)),
            Err(BlockchainError::UnknownDomain)
        );
    }

    // --- GC + grace (M8b) ---

    #[test]
    fn gc_removes_expired_domains_and_parks_them_in_grace() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        // Register at now=1000 via journaled path.
        let mut journal = UndoLog::default();
        state
            .apply_journaled_at(&register("example.uip", 1), 1000, &mut journal)
            .unwrap();
        let until = state.domain(&domain_id("example.uip")).unwrap().valid_until;
        // GC just before expiry: nothing removed.
        let mut j2 = UndoLog::default();
        state.gc_expired_journaled(until - 1, &mut j2);
        assert_eq!(state.len(), 1);
        // GC at expiry: removed, grace parked.
        state.gc_expired_journaled(until, &mut j2);
        assert_eq!(state.len(), 0);
        // During grace, re-register fails (name frozen).
        assert_eq!(
            state.apply_journaled_at(&register("example.uip", 2), until + 1, &mut j2),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
        // After grace, the name is free for anyone.
        state
            .apply_journaled_at(
                &register("example.uip", 2),
                until + DOMAIN_GRACE_SECS,
                &mut j2,
            )
            .unwrap();
        assert_eq!(
            state.domain(&domain_id("example.uip")).unwrap().owner,
            owner(2)
        );
    }

    #[test]
    fn gc_is_deterministic_and_rollback_exact() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        let mut j = UndoLog::default();
        state
            .apply_journaled_at(&register("a.uip", 1), 1000, &mut j)
            .unwrap();
        // b registered later => strictly later expiry.
        state
            .apply_journaled_at(&register("b.uip", 2), 2000, &mut j)
            .unwrap();
        let snapshot = state.clone();
        let a_until = state.domain(&domain_id("a.uip")).unwrap().valid_until;
        let mut j2 = UndoLog::default();
        // GC at a's expiry: a is removed (valid_until <= now), b
        // survives (its expiry is 1000s later).
        state.gc_expired_journaled(a_until, &mut j2);
        assert_eq!(state.len(), 1); // only b.uip survives
        state.rollback(j2);
        assert_eq!(state, snapshot);
    }

    // --- Network separation (M8b) ---

    #[test]
    fn wrong_network_transaction_is_rejected() {
        let mut state = ChainState::new(); // testnet
        let tx = Transaction::RegisterTld(RegisterTld::register_tld_on(
            scone_core::MAINNET.network_id,
            TldName::new("uip").unwrap(),
            1,
            mined_proof(&tld_challenge("uip"), "tld"),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_eq!(
            state.apply(&tx),
            Err(BlockchainError::WrongNetwork {
                tx: scone_core::MAINNET.network_id,
                chain: TESTNET.network_id,
            })
        );
        assert!(state.tld_is_empty());
    }

    #[test]
    fn mainnet_state_rejects_testnet_tx_and_vice_versa() {
        // Mainnet chain: a testnet tx is refused even with a
        // mainnet-mined… no — the PoW would fail too; the network
        // check fires FIRST, before any PoW work.
        let mut mainnet = ChainState::for_network(scone_core::MAINNET);
        let tx = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            // testnet default + EMPTY proof: rejected on network
            // alone, proving the check precedes the PoW.
            DomainName::new("example.uip").unwrap(),
            1,
            Proof::from_bytes(Vec::new()),
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert!(matches!(
            mainnet.apply(&tx),
            Err(BlockchainError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn testnet_proof_does_not_verify_as_mainnet_pow() {
        // The state rejects on the network field first; this test
        // pins the deeper property — the digest itself is separated.
        let mut mainnet = ChainState::for_network(scone_core::MAINNET);
        // Build a testnet-targeting tx but patch the network field to
        // mainnet, with a testnet-mined proof: the PoW must fail.
        let proof = mined_proof(&tld_challenge("uip"), "tld");
        let tx = Transaction::RegisterTld(RegisterTld::register_tld_on(
            scone_core::MAINNET.network_id,
            TldName::new("uip").unwrap(),
            1,
            proof,
            key(1).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert!(matches!(mainnet.apply(&tx), Err(BlockchainError::Core(_))));
    }

    // --- SMT engagement (M6a) ---

    use crate::finality::{domain_leaf_v2, tld_leaf_v2};
    use crate::smt::{Smt, smt_key};

    /// Invariant: the incrementally maintained SMT is EXACTLY the
    /// commitment of the current domain+TLD maps (naive rebuild from
    /// the maps → same root, same size). Catches any apply/GC path
    /// that forgets to sync a leaf.
    fn assert_smt_invariant(state: &ChainState) {
        let mut expect = Smt::new();
        for (id, st) in &state.domains {
            expect.insert(smt_key(id.as_bytes()), domain_leaf_v2(id, st));
        }
        for (id, st) in &state.tlds {
            expect.insert(smt_key(id.as_bytes()), tld_leaf_v2(id, st));
        }
        assert_eq!(
            state.smt().root(),
            expect.root(),
            "maintained SMT == naive rebuild of the maps"
        );
        assert_eq!(state.smt().len(), state.domains.len() + state.tlds.len());
    }

    #[test]
    fn smt_empty_state_root_is_pinned() {
        let state = ChainState::new();
        let mut top = Vec::new();
        top.extend_from_slice(b"SCONE-STATE-SMT-V1");
        top.extend_from_slice(&state.smt().root());
        assert_eq!(state.state_root_smt(), scone_crypto::hash256(&[&top]));
        assert!(state.smt().is_empty());
    }

    #[test]
    fn smt_matches_naive_rebuild_through_every_tx_kind() {
        let mut state = ChainState::new();
        assert_smt_invariant(&state);
        state.apply(&register_tld("uip", 1)).unwrap();
        assert_smt_invariant(&state);
        state.apply(&set_open("uip", 1, true)).unwrap();
        assert_smt_invariant(&state);
        state.apply(&register("a.uip", 2)).unwrap();
        assert_smt_invariant(&state);
        state.apply(&register("b.uip", 3)).unwrap();
        assert_smt_invariant(&state);
        state.apply(&update("a.uip", 2, 1)).unwrap();
        assert_smt_invariant(&state);
        state
            .apply(&renew("a.uip", 2, DOMAIN_TERM_SECS + 500))
            .unwrap();
        assert_smt_invariant(&state);
        // TLD transfer + revoke on another namespace.
        state.apply(&register_tld("com", 4)).unwrap();
        assert_smt_invariant(&state);
        let transfer = Transaction::TransferTld(scone_core::TransferTld::transfer_tld_signed(
            tld_id("com"),
            owner(5),
            key(4).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&transfer).unwrap();
        assert_smt_invariant(&state);
        let assign = Transaction::AssignDomain(scone_core::AssignDomain::assign_domain_signed(
            DomainName::new("vip.com").unwrap(),
            owner(5),
            key(5).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&assign).unwrap();
        assert_smt_invariant(&state);
        let revoke = Transaction::RevokeTld(scone_core::RevokeTld::revoke_tld_signed(
            tld_id("com"),
            key(5).public_key(),
            Signature::from_bytes([0; 64]),
        ));
        state.apply(&revoke).unwrap();
        assert_smt_invariant(&state);
        // Deterministic GC (journaled): expire a.uip — the SMT must
        // drop its leaf.
        let a_until = state.domain(&domain_id("a.uip")).unwrap().valid_until;
        let mut j = UndoLog::default();
        state.gc_expired_journaled(a_until, &mut j);
        assert_smt_invariant(&state);
        state.rollback(j);
        assert_smt_invariant(&state);
    }

    #[test]
    fn smt_rollback_restores_the_tree_bit_exact() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        let snapshot = state.clone();
        let root_before = state.state_root_smt();

        let mut journal = UndoLog::default();
        state
            .apply_journaled_at(&register("a.uip", 1), 1000, &mut journal)
            .unwrap();
        // Intermediate divergence: the engaged state (a.uip live)
        // differs from the snapshot → different SMT root.
        assert_ne!(state.state_root_smt(), root_before);
        state
            .apply_journaled_at(&update("a.uip", 1, 1), 1000, &mut journal)
            .unwrap();
        state
            .apply_journaled_at(&register("b.uip", 2), 1000, &mut journal)
            .unwrap();
        let a_until = state.domain(&domain_id("a.uip")).unwrap().valid_until;
        // GC both: a expires at its term, b (same term) too. The
        // engaged set falls back to the snapshot's (uip only — grace
        // entries are deliberately NOT engaged), but the full state
        // (grace map) still differs.
        state.gc_expired_journaled(a_until, &mut journal);
        assert_ne!(state, snapshot);

        // Rollback: the restored tree must be BIT-IDENTICAL to the
        // pre-journal tree — `ChainState: PartialEq` compares the
        // Smt field structurally (leaves, buckets, branch nodes,
        // root cache), so this is a physical, not merely logical,
        // equality check.
        state.rollback(journal);
        assert_eq!(state, snapshot);
        assert_eq!(state.state_root_smt(), root_before);
    }

    #[test]
    fn smt_root_is_order_independent() {
        // Two independent states reach the same logical state via
        // different (both valid) application orders → same SMT root.
        let mut left = ChainState::new();
        let mut right = ChainState::new();
        for state in [&mut left, &mut right] {
            state.apply(&register_tld("uip", 1)).unwrap();
            state.apply(&register_tld("com", 4)).unwrap();
            state.apply(&set_open("uip", 1, true)).unwrap();
            state.apply(&set_open("com", 4, true)).unwrap();
        }
        // left: a, b, upd a, upd b — right: b, a, upd b, upd a.
        left.apply(&register("a.uip", 2)).unwrap();
        left.apply(&register("b.uip", 3)).unwrap();
        right.apply(&register("b.uip", 3)).unwrap();
        right.apply(&register("a.uip", 2)).unwrap();
        left.apply(&update("a.uip", 2, 1)).unwrap();
        left.apply(&update("b.uip", 3, 1)).unwrap();
        right.apply(&update("b.uip", 3, 1)).unwrap();
        right.apply(&update("a.uip", 2, 1)).unwrap();

        assert_eq!(left, right);
        assert_eq!(left.state_root_smt(), right.state_root_smt());
        assert_smt_invariant(&left);
        assert_smt_invariant(&right);
    }

    #[test]
    fn smt_distinguishes_distinct_logical_states() {
        let base = |state: &mut ChainState| {
            state.apply(&register_tld("uip", 1)).unwrap();
            state.apply(&set_open("uip", 1, true)).unwrap();
            state.apply(&register("a.uip", 2)).unwrap();
        };
        let mut a = ChainState::new();
        let mut b = ChainState::new();
        let mut c = ChainState::new();
        base(&mut a);
        base(&mut b);
        base(&mut c);
        // a: untouched; b: one more update; c: renewal instead.
        b.apply(&update("a.uip", 2, 1)).unwrap();
        c.apply(&renew("a.uip", 2, DOMAIN_TERM_SECS + 1)).unwrap();
        assert_ne!(a.state_root_smt(), b.state_root_smt());
        assert_ne!(a.state_root_smt(), c.state_root_smt());
        assert_ne!(b.state_root_smt(), c.state_root_smt());
        // The canonical V2 root distinguishes them too (same leaves).
        assert_ne!(a.state_root(), b.state_root());
        assert_ne!(a.state_root(), c.state_root());
    }

    #[test]
    fn failed_apply_leaves_smt_unchanged() {
        let mut state = ChainState::new();
        seed_open_uip(&mut state);
        state.apply(&register("example.uip", 1)).unwrap();
        let snapshot = state.clone();
        let root = state.state_root_smt();
        let _ = state.apply(&register("example.uip", 9));
        let _ = state.apply(&update("example.uip", 9, 1));
        let _ = state.apply(&update("example.uip", 1, 7));
        assert_eq!(state, snapshot);
        assert_eq!(state.state_root_smt(), root);
    }
}
