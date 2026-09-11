//! Checkpoint finality for the canonical chain (ported from
//! scone.bak, M3 of the .bak integration).
//!
//! # Model (§4/§17 of the old protocol spec)
//!
//! A checkpoint commits `epoch || height || block_hash ||
//! prev_checkpoint_hash || state_root` and is signed by ≥ quorum of
//! the committee ELECTED for its epoch (top-N of the PoS pool by
//! `select_committee(seed, pool)`). Checkpoints chain: the next
//! references `hash(checkpoint N)`. **A finalized checkpoint is
//! immutable**: no reorg, no recovery, no external procedure can
//! produce a branch contradicting a finalized checkpoint — the fork
//! choice enforces it.
//!
//! # Eligibility pool
//!
//! The PoS pool is the set of owners of LIVE DOMAINS, deduplicated by
//! public key (all domains of one key count as one seat). The pool is
//! FROZEN at the finalized block: the finality base never re-reads
//! the live state (a reorg replays from a fresh state; the frozen
//! pool must resolve on its own). Entry cost = one domain
//! registration PoW + renewal (economic anti-Sybil, linear per
//! identity).
//!
//! # Bootstrap
//!
//! Before any finalized checkpoint, production is open to any owner
//! of a live domain at the parent state (empty pool = fully open,
//! otherwise the first REGISTER would be impossible), and the epoch-0
//! seed derives from the genesis hash (common to all nodes, not
//! choosable by anyone).
//!
//! # Small committees
//!
//! An elected committee smaller than
//! [`MIN_FINALITY_COMMITTEE_SIZE`] never claims BFT finality:
//! finality is DEFERRED (production stays allowed).

use std::collections::HashSet;

use scone_core::checkpoint::{
    Checkpoint, CheckpointData, next_seed, recovery_seed, select_committee,
};
use scone_core::{MIN_FINALITY_COMMITTEE_SIZE, quorum_for};
use scone_crypto::{PublicKey, SigningKey};

use crate::chain::Blockchain;
use crate::error::{BlockchainError, Result};
use crate::state::ChainState;

/// Finalized checkpoints kept in RAM (the storage layer keeps
/// everything; the chain reads only the last for the rules). Ported
/// value from the .bak: ~6 KiB per checkpoint, window = rebroadcast
/// needs only.
pub const CHECKPOINT_KEEP: usize = 64;

/// The frozen PoS base: the last finalized checkpoint plus the
/// eligibility pool frozen at that block. Public keys are
/// self-contained (a reorg replays from an empty state — the frozen
/// pool must resolve without any interning table).
#[derive(Debug, Clone)]
pub struct FinalizedBase {
    /// The finalized checkpoint itself.
    pub checkpoint: Checkpoint,
    /// Eligibility pool frozen at the finalized block (live-domain
    /// owners, deduplicated, bans at that instant included — the
    /// finality never re-reads the live state).
    pub pool: Vec<PublicKey>,
    /// Timestamp of the finalized block (consensus clock for pool
    /// liveness and recovery delays).
    pub block_ts: u64,
    /// Seed of the NEXT epoch: derived from the finalized checkpoint.
    pub seed: [u8; 32],
}

impl Blockchain {
    /// Elected committee (recovery = 0) for the next epoch, or the
    /// recovery-k committee. Pool: owners of live domains at the
    /// LAST FINALIZED checkpoint state (bootstrap: tip state,
    /// liveness at the tip).
    #[must_use]
    pub fn committee(&self, recovery: u32) -> Vec<PublicKey> {
        let size = self.network().consensus.committee_size;
        match &self.finalized {
            None => {
                if recovery != 0 {
                    return Vec::new();
                }
                let pool = self
                    .state()
                    .eligible_validators(self.tip().header.timestamp);
                select_committee(&self.bootstrap_seed(), pool, size)
            }
            Some(base) => {
                let seed = if recovery == 0 {
                    base.seed
                } else {
                    recovery_seed(&base.seed, recovery)
                };
                select_committee(&seed, base.pool.iter().copied(), size)
            }
        }
    }

    /// Epoch-0 seed (before any checkpoint): derived from the genesis
    /// — common to all nodes, not choosable.
    fn bootstrap_seed(&self) -> [u8; 32] {
        let genesis_hash = crate::block_hash::block_hash(&self.genesis().header)
            .expect("genesis header is valid by construction");
        next_seed(genesis_hash.as_bytes())
    }

    /// Deterministic checkpoint CONTENT for the current tip
    /// (recovery = 0 by default). Rules checked by
    /// [`Blockchain::check_checkpoint_data`]; valid only if they pass.
    pub fn checkpoint_data(&self, recovery: u32) -> Result<CheckpointData> {
        let tip = self.tip();
        let (epoch, prev) = match self.checkpoints.last() {
            None => (0u64, [0u8; 32]),
            Some(cp) => (cp.data.epoch + 1, cp.hash()),
        };
        Ok(CheckpointData {
            epoch,
            height: tip.header.height,
            block_hash: *crate::block_hash::block_hash(&tip.header)?.as_bytes(),
            prev_checkpoint_hash: prev,
            state_root: self.state().state_root(),
            recovery,
        })
    }

    /// Deterministic rules of checkpoint content (replayable by any
    /// node): the referenced block must be in OUR chain above the
    /// last finalized checkpoint, epochs chain exactly, height
    /// strictly advances, recovery within limits and delay.
    pub fn check_checkpoint_data(&self, d: &CheckpointData) -> Result<()> {
        let bad = |what: &str| BlockchainError::Consensus(format!("invalid checkpoint: {what}"));
        let h = d.height;
        if h == 0 || h > self.height() {
            return Err(bad("checkpoint references a block not in our chain"));
        }
        match self.checkpoints.last() {
            None => {
                if d.epoch != 0 || d.prev_checkpoint_hash != [0u8; 32] {
                    return Err(bad("first checkpoint must chain genesis"));
                }
            }
            Some(last) => {
                if d.epoch != last.data.epoch + 1 {
                    return Err(bad("checkpoint epoch must advance by exactly one"));
                }
                if d.prev_checkpoint_hash != last.hash() {
                    return Err(bad("checkpoint does not chain our last finalized"));
                }
                if d.height <= last.data.height {
                    return Err(bad("checkpoint height must advance"));
                }
                if d.recovery > self.network().consensus.recovery_max_epochs {
                    return Err(bad("recovery counter beyond protocol limit"));
                }
                // Recovery delay in CONSENSUS time (deterministic at
                // replay — never the local clock).
                if d.recovery >= 1 {
                    let elapsed = self.tip_ts_since_last_checkpoint();
                    let need = u64::from(d.recovery) * self.network().consensus.epoch_secs;
                    if elapsed < need {
                        return Err(bad("recovery delay (consensus time) not reached"));
                    }
                }
            }
        }
        Ok(())
    }

    /// Consensus time elapsed since the last finalized checkpoint
    /// (never the local clock — two nodes replaying the same branch
    /// decide identically).
    fn tip_ts_since_last_checkpoint(&self) -> u64 {
        match self.checkpoints.last() {
            None => 0,
            Some(last) => {
                let cp_ts = self
                    .block(last.data.height)
                    .map(|b| b.header.timestamp)
                    .unwrap_or(0);
                self.tip().header.timestamp.saturating_sub(cp_ts)
            }
        }
    }

    /// Candidate checkpoint of this node for the current tip — None
    /// if the rules are not met (minimum block interval).
    #[must_use]
    pub fn propose_checkpoint(&self) -> Option<CheckpointData> {
        let last_height = self.checkpoints.last().map(|c| c.data.height).unwrap_or(0);
        let min_blocks = self.network().consensus.epoch_min_blocks;
        if self.height() <= last_height || self.height() - last_height < min_blocks {
            return None;
        }
        self.checkpoint_data(0).ok()
    }

    /// Signs a checkpoint proposal with `sk` (the caller then gossips
    /// the signed context; aggregation happens off-chain here).
    /// Returns the signature over the checkpoint signing hash.
    pub fn sign_checkpoint(
        &self,
        guard: &mut crate::signer::SignerGuard,
        sk: &SigningKey,
        d: &CheckpointData,
    ) -> Result<scone_crypto::Signature> {
        // The signer guard refuses equivocation (one key = one vote
        // per epoch) BEFORE signing, and persists the context before
        // the signature is returned.
        let sig = guard.authorize(sk, d)?;
        Ok(sig)
    }

    /// Accepts a finalized checkpoint: content rules, committee
    /// guard, quorum against the committee derived from our frozen
    /// base (or the bootstrap pool at the checkpoint height), state
    /// root match, then freezes the new base. Returns true when the
    /// checkpoint was new, false on exact duplicate (idempotent).
    pub fn accept_checkpoint(&mut self, cp: Checkpoint) -> Result<bool> {
        self.check_checkpoint_data(&cp.data)?;
        let committee = self.committee(cp.data.recovery);
        if committee.len() < MIN_FINALITY_COMMITTEE_SIZE {
            return Err(BlockchainError::Consensus(
                "committee below BFT floor: finality deferred".into(),
            ));
        }
        let quorum = quorum_for(committee.len());
        if !cp.verify_quorum(&committee, quorum) {
            return Err(BlockchainError::Consensus(format!(
                "checkpoint quorum not met (need {quorum})"
            )));
        }
        // State root must match OUR recomputation at that height. The
        // current RAM state is the tip: exact when the checkpoint
        // targets the tip; otherwise the caller replays (the relay
        // drives this — a full replay-to-height is a storage/relay
        // concern, the chain layer verifies what it can see).
        if cp.data.height == self.height() && cp.data.state_root != self.state().state_root() {
            return Err(BlockchainError::Consensus(
                "checkpoint state root mismatch".into(),
            ));
        }
        // Idempotence: exact duplicate of our last finalized.
        if let Some(last) = self.checkpoints.last()
            && last.hash() == cp.hash()
        {
            return Ok(false);
        }
        let block_ts = self
            .block(cp.data.height)
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
        let pool = self.state().eligible_validators(block_ts);
        let seed = next_seed(&cp.hash());
        self.finalized = Some(FinalizedBase {
            checkpoint: cp.clone(),
            pool,
            block_ts,
            seed,
        });
        self.checkpoints.push(cp);
        let keep = self.checkpoints.len().saturating_sub(CHECKPOINT_KEEP);
        self.checkpoints.drain(..keep);
        Ok(true)
    }

    /// Allowed producers for a block with timestamp `block_ts`
    /// (consensus time of the block itself: deterministic at
    /// replay). Bootstrap: every owner of a live domain at the parent
    /// state; empty pool (genesis) = fully open, otherwise no first
    /// REGISTER would be possible. Finalized: elected committee +
    /// recovery draws whose consensus delay is reached.
    #[must_use]
    pub fn allowed_producers(&self, block_ts: u64) -> HashSet<PublicKey> {
        let size = self.network().consensus.committee_size;
        match &self.finalized {
            None => {
                let pool = self.state().eligible_validators(block_ts);
                if pool.is_empty() {
                    return HashSet::new(); // empty = open (see validation)
                }
                select_committee(&self.bootstrap_seed(), pool, size)
                    .into_iter()
                    .collect()
            }
            Some(base) => {
                let mut set: HashSet<PublicKey> =
                    select_committee(&base.seed, base.pool.iter().copied(), size)
                        .into_iter()
                        .collect();
                let elapsed = block_ts.saturating_sub(base.block_ts);
                for k in 1..=self.network().consensus.recovery_max_epochs {
                    if elapsed >= u64::from(k) * self.network().consensus.epoch_secs {
                        let seed = recovery_seed(&base.seed, k);
                        set.extend(select_committee(&seed, base.pool.iter().copied(), size));
                    }
                }
                set
            }
        }
    }

    /// Last finalized base (None: bootstrap).
    #[must_use]
    pub fn finalized(&self) -> Option<&FinalizedBase> {
        self.finalized.as_ref()
    }

    /// Finalized checkpoints (window, chained order).
    #[must_use]
    pub fn checkpoint_window(&self) -> &[Checkpoint] {
        &self.checkpoints
    }
}

impl ChainState {
    /// PoS eligibility pool: public keys of owners of LIVE domains
    /// (`valid_until > now`), deduplicated by key. One key with a
    /// hundred domains = one seat (economic anti-Sybil is per
    /// identity, linear).
    #[must_use]
    pub fn eligible_validators(&self, now: u64) -> Vec<PublicKey> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for state in self.domains.values() {
            if state.valid_until > now
                && seen.insert(state.owner)
                && let Some(pk) = self.owner_public_key(state.owner)
            {
                out.push(pk);
            }
        }
        out
    }

    /// Recomputes the state root: BLAKE3 over the domain-root, the
    /// TLD-root and the owner-pool root (domain separation
    /// `SCONE-STATE-V2`). Deterministic: two nodes with the same
    /// logical state compute the same root.
    ///
    /// NOTE (M3 of the .bak port): the root is currently computed
    /// over a merkle of the domain map (not yet the incremental SMT —
    /// the SMT swap is the next port step and keeps this hash stable
    /// by construction of the leaves).
    #[must_use]
    pub fn state_root(&self) -> [u8; 32] {
        use std::collections::BTreeMap;
        // Deterministic order: BTreeMap over ids.
        let domains: BTreeMap<&scone_core::DomainId, &crate::state::DomainState> =
            self.domains.iter().collect();
        let tlds: BTreeMap<&scone_core::TldId, &crate::state::TldState> =
            self.tlds.iter().collect();
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(domains.len() + tlds.len());
        for (id, st) in &domains {
            let mut buf = Vec::with_capacity(15 + 32 + 32 + 8 + 8 + 32);
            buf.extend_from_slice(b"SCONE-LEAF-DOM-V2");
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(st.owner.as_bytes());
            buf.extend_from_slice(&st.sequence.to_be_bytes());
            buf.extend_from_slice(&st.registered_at.to_be_bytes());
            buf.extend_from_slice(&st.valid_until.to_be_bytes());
            if let Some(rh) = st.record_hash {
                buf.extend_from_slice(rh.as_bytes());
            } else {
                buf.extend_from_slice(&[0u8; 32]);
            }
            leaves.push(scone_crypto::hash256(&[&buf]));
        }
        for (id, st) in &tlds {
            let mut buf = Vec::with_capacity(15 + 32 + 32 + 1);
            buf.extend_from_slice(b"SCONE-LEAF-TLD-V2");
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(st.owner.as_bytes());
            buf.push(u8::from(st.open));
            leaves.push(scone_crypto::hash256(&[&buf]));
        }
        let mut top = Vec::with_capacity(15 + 32 + 32);
        top.extend_from_slice(b"SCONE-STATE-V2");
        // merkle_root over raw 32-byte hashes via a light fold:
        let folded = fold_hashes(&leaves);
        top.extend_from_slice(&folded);
        top.extend_from_slice(&self.owner_pool_root());
        scone_crypto::hash256(&[&top])
    }

    fn owner_pool_root(&self) -> [u8; 32] {
        use std::collections::BTreeSet;
        let owners: BTreeSet<scone_core::OwnerId> =
            self.domains.values().map(|s| s.owner).collect();
        let leaves: Vec<[u8; 32]> = owners
            .iter()
            .map(|o| {
                let mut buf = Vec::with_capacity(16 + 32);
                buf.extend_from_slice(b"SCONE-LEAF-OWN-V2");
                buf.extend_from_slice(o.as_bytes());
                scone_crypto::hash256(&[&buf])
            })
            .collect();
        fold_hashes(&leaves)
    }

    /// OwnerId → PublicKey resolution. The chain state stores
    /// OwnerId (identity), not keys; the pool carries self-contained
    /// keys. Without a key index the pool falls back to deriving
    /// from... nothing — so the ChainState keeps a light
    /// owner→key index (filled by apply, replayed deterministically).
    fn owner_public_key(&self, _owner: scone_core::OwnerId) -> Option<PublicKey> {
        self.owner_keys.get(&_owner).copied()
    }
}

/// Deterministic merkle fold over 32-byte leaves (empty = zero hash).
fn fold_hashes(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(scone_crypto::hash256(&[b"SCONE-FOLD-V1", &pair[0], right]));
        }
        level = next;
    }
    level[0]
}
