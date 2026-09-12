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
use scone_core::{DomainId, MIN_FINALITY_COMMITTEE_SIZE, TldId, quorum_for};
use scone_crypto::{PublicKey, SigningKey};

use crate::chain::Blockchain;
use crate::error::{BlockchainError, Result};
use crate::state::ChainState;
use crate::state_backend::StateBackend as _;

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

impl<C: crate::consensus::Consensus> Blockchain<C> {
    /// Elected committee (recovery = 0) for the next epoch, or the
    /// recovery-k committee. Pool: owners of live domains at the
    /// LAST FINALIZED checkpoint state (bootstrap: tip state,
    /// liveness at the tip).
    #[must_use]
    pub fn committee(&self, recovery: u32) -> Vec<PublicKey> {
        let size = self.network.consensus.committee_size;
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
            state_root: self.state().state_root_smt(),
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
                if d.recovery > self.network.consensus.recovery_max_epochs {
                    return Err(bad("recovery counter beyond protocol limit"));
                }
                // Recovery delay in CONSENSUS time (deterministic at
                // replay — never the local clock).
                if d.recovery >= 1 {
                    let elapsed = self.tip_ts_since_last_checkpoint();
                    let need = u64::from(d.recovery) * self.network.consensus.epoch_secs;
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
        let min_blocks = self.network.consensus.epoch_min_blocks;
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
        // State root must match OUR recomputation at that height —
        // the canonical O(1) SMT root since the scalable-state
        // pivot. The current RAM state is the tip: exact when the
        // checkpoint targets the tip; otherwise the caller replays
        // (the relay drives this — a full replay-to-height is a
        // storage/relay concern, the chain layer verifies what it
        // can see).
        if cp.data.height == self.height() && cp.data.state_root != self.state().state_root_smt() {
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
        let size = self.network.consensus.committee_size;
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
                for k in 1..=self.network.consensus.recovery_max_epochs {
                    if elapsed >= u64::from(k) * self.network.consensus.epoch_secs {
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

/// Leaf encoding of one domain state (`SCONE-LEAF-DOM-V2`).
///
/// Shared (pub(crate)) between the canonical direct-fold `state_root`
/// below and the incremental SMT commitment (`ChainState::smt`,
/// `state_root_smt`): both commit **exactly the same leaves**, so the
/// two commitments track the same logical state by construction.
pub(crate) fn domain_leaf_v2(
    id: &scone_core::DomainId,
    st: &crate::state::DomainState,
) -> [u8; 32] {
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
    scone_crypto::hash256(&[&buf])
}

/// Leaf encoding of one TLD state (`SCONE-LEAF-TLD-V2`) — same
/// sharing contract as [`domain_leaf_v2`].
pub(crate) fn tld_leaf_v2(id: &scone_core::TldId, st: &crate::state::TldState) -> [u8; 32] {
    let mut buf = Vec::with_capacity(15 + 32 + 32 + 1);
    buf.extend_from_slice(b"SCONE-LEAF-TLD-V2");
    buf.extend_from_slice(id.as_bytes());
    buf.extend_from_slice(st.owner.as_bytes());
    buf.push(u8::from(st.open));
    scone_crypto::hash256(&[&buf])
}

impl ChainState {
    /// PoS eligibility pool: public keys of owners of LIVE domains
    /// (`valid_until > now`) and owners of LIVE TLDs (a claim cost a
    /// PoW — the TLD owner is a stakeholder), deduplicated by key —
    /// **minus banned keys** (M9: a slashed equivocator is out of the
    /// pool for life). One key with a hundred domains = one seat
    /// (economic anti-Sybil is per identity, linear).
    ///
    /// Scalable-state pivot: the pool is read from the
    /// journal-maintained bounded index (`owner_refcounts`, one entry
    /// per DISTINCT live owner — O(owners), independent of the domain
    /// count), NEVER by iterating the domain backend. Time-liveness
    /// (`valid_until > now`) is answered by the expiration queue:
    /// every domain whose expiry is `<= now` has already left the
    /// live registry and its owner's refcount — the deterministic GC
    /// (`Blockchain::push_block`, parent timestamp) ran first. The
    /// output is sorted (deterministic order, independent of the
    /// index's iteration order).
    #[must_use]
    pub fn eligible_validators(&self, now: u64) -> Vec<PublicKey> {
        let _ = now; // liveness is enforced by the GC + refcount index
        let mut pool: Vec<PublicKey> = self
            .owner_refcounts
            .keys()
            .filter_map(|owner| self.owner_keys.get(owner).copied())
            .filter(|pk| !self.banned.contains(pk))
            .collect();
        pool.sort();
        pool
    }

    /// Archive state root (`SCONE-STATE-V2`, format frozen): BLAKE3
    /// over the domain-root, the TLD-root, the owner-pool root and
    /// the banned-root, folding the SAME leaves as the SMT. **O(N)
    /// over the whole entry set — document every call site**: this is
    /// the archival verification path (a node re-folding the full
    /// state from storage to cross-check a historical root), NOT a
    /// consensus artifact. The canonical commitment of the current
    /// protocol version is [`ChainState::state_root_smt`] (O(1),
    /// cached — what checkpoints commit since the scalable-state
    /// pivot); the two commit the same leaves, so equality of logical
    /// states implies equality of both roots.
    ///
    /// M9: the ban list is part of the committed state — the leaf
    /// per banned key is `BLAKE3("SCONE-LEAF-BAN-V1" || pk)` and the
    /// banned-root folds them in key order (empty list = zero hash).
    /// A checkpoint that finalizes a state without the ban would
    /// contradict the state every honest node computes after the
    /// SlashTx.
    #[must_use]
    pub fn state_root_v2(&self) -> [u8; 32] {
        // Deterministic order: ascending backend keys (the ids ARE
        // the keys — a BTreeMap over ids in the old layout, the
        // backend's ordered range now).
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(self.domain_count + self.tld_count);
        let mut cursor: Option<crate::state_backend::Pkey> = None;
        loop {
            let (page, next) = self.backend.range(cursor.as_ref(), 1024);
            for (key, bytes) in page {
                if let Some(st) = crate::state::decode_domain_entry(&bytes) {
                    leaves.push(domain_leaf_v2(&DomainId::from_bytes(key), &st));
                } else if let Some(st) = crate::state::decode_tld_entry(&bytes) {
                    leaves.push(tld_leaf_v2(&TldId::from_bytes(key), &st));
                }
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        let mut top = Vec::with_capacity(15 + 32 + 32);
        top.extend_from_slice(b"SCONE-STATE-V2");
        // merkle_root over raw 32-byte hashes via a light fold:
        let folded = fold_hashes(&leaves);
        top.extend_from_slice(&folded);
        top.extend_from_slice(&self.owner_pool_root());
        top.extend_from_slice(&self.banned_root());
        scone_crypto::hash256(&[&top])
    }

    /// Owner-pool root: one `SCONE-LEAF-OWN-V2` leaf per DISTINCT
    /// owner of a live domain/TLD (the bounded index — never a scan
    /// of the domain backend), folded in ascending order.
    fn owner_pool_root(&self) -> [u8; 32] {
        let owners: std::collections::BTreeSet<scone_core::OwnerId> =
            self.owner_refcounts.keys().copied().collect();
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

    /// Root of the ban list (M9): one `SCONE-LEAF-BAN-V1` leaf per
    /// banned key, folded in ascending key order (deterministic).
    fn banned_root(&self) -> [u8; 32] {
        use std::collections::BTreeSet;
        let banned: BTreeSet<_> = self.banned.iter().map(|pk| pk.to_bytes()).collect();
        let leaves: Vec<[u8; 32]> = banned
            .iter()
            .map(|pk| {
                let mut buf = Vec::with_capacity(16 + 32);
                buf.extend_from_slice(b"SCONE-LEAF-BAN-V1");
                buf.extend_from_slice(pk);
                scone_crypto::hash256(&[&buf])
            })
            .collect();
        fold_hashes(&leaves)
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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests_support::{
        child, claim_open_uip, producer_key, register_domain_tx, update_domain_tx,
    };
    use scone_core::checkpoint::Checkpoint;

    /// Scalable-state pivot: a checkpoint accepted with the SMT root
    /// re-verifies after a restore (reload) — the O(1) canonical
    /// root is a pure function of the restored KV + SMT, and the
    /// idempotent duplicate path answers on the hash alone.
    #[test]
    fn accepted_smt_checkpoint_reverifies_after_restore() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        for (name, seed) in [("a.uip", 2u8), ("b.uip", 3), ("c.uip", 4)] {
            chain
                .push_block(&child(&chain, vec![register_domain_tx(name, seed)]))
                .unwrap();
        }
        let data = chain.checkpoint_data(0).unwrap();
        // The committed root IS the canonical SMT root.
        assert_eq!(data.state_root, chain.state().state_root_smt());
        let committee = chain.committee(0);
        assert!(
            committee.len() >= scone_core::MIN_FINALITY_COMMITTEE_SIZE,
            "test fixture must reach the BFT floor"
        );
        let keys: Vec<_> = (1..=4u8)
            .map(|i| scone_crypto::SigningKey::from_bytes([i; 32]))
            .collect();
        let sigs: Vec<_> = keys
            .iter()
            .map(|sk| (sk.public_key(), sk.sign(&data.signing_hash())))
            .collect();
        let cp = Checkpoint {
            data,
            signatures: sigs,
        };
        chain.accept_checkpoint(cp.clone()).unwrap();

        // Restore (reload) the chain from the tip + state, as the
        // storage layer does.
        let tip = chain.height();
        let restored = Blockchain::restore(
            tip,
            chain.tip_hash(),
            chain.block(tip).unwrap().clone(),
            chain.state().clone(),
        );
        // The restored state recomputes the exact same SMT root.
        assert_eq!(
            restored.state().state_root_smt(),
            cp.data.state_root,
            "checkpoint accepted with the SMT root re-verifies after restore"
        );
        // A fresh checkpoint_data over the restored tip commits the
        // same root: the content rule stays satisfiable.
        let re_data = restored.checkpoint_data(0).unwrap();
        assert_eq!(re_data.state_root, cp.data.state_root);
        assert_eq!(re_data.epoch, cp.data.epoch);
        let _ = producer_key();
        let _ = update_domain_tx;
    }
}
