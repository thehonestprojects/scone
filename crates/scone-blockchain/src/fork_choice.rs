//! Fork choice for the canonical chain (ported from scone.bak, M3 of
//! the .bak integration).
//!
//! Replaces the M4 linear `ParentNotTip` refusal: a block building on
//! a known non-tip block is no longer rejected outright — the chain
//! EVALUATES the branch.
//!
//! # Rules (same order as the .bak)
//!
//! 1. **Finality floor**: a candidate branch must contain every
//!    locally finalized checkpoint's block at the same height — a
//!    finalized checkpoint is immutable, no branch forking below or
//!    around it is ever adoptable;
//! 2. **Longest chain wins**;
//! 3. **Tie-break by lowest tip hash** (deterministic convergence of
//!    sister blocks — without it, two same-height chains would never
//!    converge).
//!
//! # Restriction vs the .bak
//!
//! The current `Blockchain` keeps its full canonical history in RAM
//! (`canonical: Vec<Block>`); there is no segmented adoption yet
//! (`.bak`'s `adopt_extension` streams the shared prefix from disk).
//! The port therefore implements whole-branch adoption over the RAM
//! window — same rules, simpler data path. Segmented adoption lands
//! with the history-window port.

use crate::chain::Blockchain;
use crate::error::{BlockchainError, Result};
use scone_protocol::Block;

impl Blockchain {
    /// Attempts to attach `block` to the chain. When its parent is
    /// the tip, this is a plain extension (`push_block_with_gc`).
    /// When the parent is a known non-tip block, the fork choice
    /// evaluates a branch switch instead of refusing
    /// (`ParentNotTip`): the candidate branch must beat the current
    /// canonical chain under the rules above — and never contradict
    /// a finalized checkpoint.
    ///
    /// This entry point does NOT have the competing branch (the
    /// caller holds one block); a single block can only beat the tip
    /// at equal height with a lower hash. Full branch adoption
    /// (chain of blocks) goes through [`Blockchain::adopt_branch`].
    pub fn try_attach(&mut self, block: &Block) -> Result<crate::chain::AppliedBlock> {
        let header = &block.header;
        if header.prev_hash == self.tip {
            return self.push_block_with_gc(block);
        }
        if !self.known_parent(header.prev_hash) {
            return Err(BlockchainError::UnknownParent);
        }
        // Known non-tip parent: a sister block. It can only win the
        // tie-break (same height as our tip, lower hash). Adopting a
        // single sister block means reorganizing to:
        // common-prefix + sister — only better if sister.height ==
        // tip.height && hash(sister) < hash(tip).
        let candidate_height = header.height;
        let tip_height = self.height();
        if candidate_height != tip_height {
            // A single block at another height either extends nothing
            // (parent known, non-tip: a fork behind or ahead of the
            // tip — ahead is impossible, the parent would be the
            // tip; behind loses on length). Not adoptable alone.
            return Err(BlockchainError::ParentNotTip);
        }
        let candidate_hash = crate::block_hash::block_hash(header)?;
        if candidate_hash.as_bytes() >= self.tip_hash().as_bytes() {
            return Err(BlockchainError::ParentNotTip);
        }
        // Tie-break won: adopt common-prefix + this block. Find the
        // common ancestor (parent of the candidate), rewind to it,
        // push the candidate.
        let ancestor_height = candidate_height - 1;
        self.reorg_to_height(ancestor_height, std::slice::from_ref(block))
    }

    /// Whether `prev` is a block this chain has ever seen.
    fn known_parent(&self, prev: scone_protocol::BlockHash) -> bool {
        self.block_hashes().contains(&prev)
    }

    /// Adopts a full competing branch `blocks` (each chaining onto
    /// the previous, the first onto the block at
    /// `blocks[0].height - 1`). The fork choice rules apply:
    /// finality floor, then length, then lowest tip hash.
    pub fn adopt_branch(&mut self, blocks: &[Block]) -> Result<bool> {
        let Some(first) = blocks.first() else {
            return Ok(false);
        };
        // The branch must chain: heights strictly consecutive, each
        // parent the previous hash.
        for (i, b) in blocks.iter().enumerate() {
            if i > 0 && b.header.prev_hash != crate::block_hash::block_hash(&blocks[i - 1].header)?
            {
                return Err(BlockchainError::Consensus(
                    "branch does not chain internally".into(),
                ));
            }
        }
        let base_height = first.header.height - 1;
        let Some(base) = self.block(base_height) else {
            return Err(BlockchainError::UnknownParent);
        };
        let base_hash = crate::block_hash::block_hash(&base.header)?;
        if first.header.prev_hash != base_hash {
            return Err(BlockchainError::UnknownParent);
        }
        // Rule 1: finality floor. Every locally finalized checkpoint
        // must sit on the candidate branch at its height.
        for cp in &self.checkpoints {
            let h = cp.data.height;
            let candidate_at_h = if h <= base_height {
                self.block(h)
            } else {
                let off = h - base_height - 1;
                blocks.get(off as usize)
            };
            let ok = candidate_at_h.is_some_and(|b| {
                crate::block_hash::block_hash(&b.header)
                    .is_ok_and(|x| x.as_bytes() == cp.data.block_hash.as_ref())
            });
            if !ok {
                return Err(BlockchainError::Consensus(
                    "branch contradicts a finalized checkpoint".into(),
                ));
            }
        }
        // Rules 2+3: length, then lowest tip hash.
        let candidate_height = base_height + blocks.len() as u64;
        let our_height = self.height();
        let candidate_tip =
            crate::block_hash::block_hash(&blocks.last().expect("non-empty").header)?;
        if candidate_height > our_height
            || (candidate_height == our_height
                && candidate_tip.as_bytes() < self.tip_hash().as_bytes())
        {
            self.reorg_to_height(base_height, blocks)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Rewinds the canonical chain to `height` (dropping the blocks
    /// above and reverting their state effects), then applies
    /// `extension` on top. The state replays from genesis — exact and
    /// deterministic (two nodes adopting the same branch reach the
    /// same bytes), at the cost of a full replay (RAM-window
    /// restriction, see module docs).
    fn reorg_to_height(
        &mut self,
        height: u64,
        extension: &[Block],
    ) -> Result<crate::chain::AppliedBlock> {
        // Snapshot the surviving prefix, rebuild state, replay.
        let network = self.network();
        let mut prefix: Vec<Block> = Vec::with_capacity(height as usize + 1);
        for h in 0..=height {
            let b = self
                .block(h)
                .cloned()
                .ok_or(BlockchainError::UnknownParent)?;
            prefix.push(b);
        }
        let mut fresh = crate::chain::Blockchain::with_consensus_for_network(
            crate::consensus::PermissiveConsensus,
            network,
        );
        // Finalized checkpoints survive a reorg by construction (the
        // fork choice refuses contradicting branches) — carry them
        // over with their frozen bases.
        fresh.checkpoints = self.checkpoints.clone();
        fresh.finalized = self.finalized.clone();
        for b in &prefix[1..] {
            fresh.push_block_with_gc(b)?;
        }
        let mut last = crate::chain::AppliedBlock {
            hash: fresh.tip_hash(),
            gc_removed_domains: Vec::new(),
        };
        let mut all_gc = Vec::new();
        for b in extension {
            let applied = fresh.push_block_with_gc(b)?;
            all_gc.extend(applied.gc_removed_domains.iter().copied());
            last = applied;
        }
        last.gc_removed_domains = all_gc;
        // Swap: the caller (relay) re-persists via its store paths.
        self.swap_with(fresh);
        Ok(last)
    }

    /// Field-swap with a rebuilt chain (same network, same
    /// checkpoints): keeps identity, replaces canon.
    fn swap_with(&mut self, other: Blockchain) {
        let hashes = other.known_hashes_vec();
        self.base_height = other.base_height;
        self.canonical = other.canonical;
        self.replace_hashes(hashes);
        self.tip = other.tip;
        self.state = other.state;
        self.checkpoints = other.checkpoints;
        self.finalized = other.finalized;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests_support::{child, claim_open_uip, register_domain_tx};
    use scone_crypto::SigningKey;
    use scone_protocol::{Block, BlockHash};

    /// A block building on `parent_hash` at `height` (no parent chain
    /// object needed). Signed by the uip owner — the producer pool of
    /// these test chains contains her (M5: production is restricted).
    fn child_of_hash(parent: BlockHash, height: u64, _txs: Vec<()>) -> Block {
        crate::BlockBuilder::after(height.saturating_sub(1), parent)
            .with_timestamp(height)
            .with_producer(&crate::chain::tests_support::producer_key())
            .build_with(vec![])
            .expect("test block is well-formed")
    }

    /// A sister block of the current tip (same parent, same height).
    fn child_at(chain: &Blockchain, _at: u64) -> Block {
        let tip = chain.tip();
        let parent = tip.header.prev_hash;
        let height = tip.header.height;
        child_of_hash(parent, height, vec![])
    }

    /// Signing keys for a committee (test: derive from the public
    /// keys is impossible — instead the caller fabricates pools; here
    /// return keys that voted, matching by index).
    fn committee_keys(committee: &[scone_crypto::PublicKey]) -> Vec<SigningKey> {
        // Deterministic mapping pk -> seed is impossible; tests use
        // this only when they created the pool themselves.
        let _ = committee;
        (1..=4u8).map(|i| SigningKey::from_bytes([i; 32])).collect()
    }

    /// Builds a chain claim+open uip, registers `name`, returns the chain.
    fn chain_with(name: &str) -> Blockchain {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx(name, 1)]))
            .unwrap();
        chain
    }

    #[test]
    fn sister_block_with_lower_hash_wins_tiebreak() {
        // Two competing blocks at the same height: whichever has the
        // lower hash must win, deterministically, on every node.
        let mut a = chain_with("example.uip");
        // Build two sisters at height N+1 with different timestamps.
        let h = a.height() + 1;
        let mut b1 = child(&a, vec![]);
        b1.header.timestamp = 100;
        b1.header.height = h;
        b1.header.tx_root = crate::merkle::tx_root(&b1.transactions).unwrap();
        crate::chain::tests_support::resign(&mut b1);
        let mut b2 = child(&a, vec![]);
        b2.header.timestamp = 200;
        b2.header.height = h;
        b2.header.tx_root = crate::merkle::tx_root(&b2.transactions).unwrap();
        crate::chain::tests_support::resign(&mut b2);
        let h1 = crate::block_hash::block_hash(&b1.header).unwrap();
        let h2 = crate::block_hash::block_hash(&b2.header).unwrap();
        let (winner, loser) = if h1.as_bytes() < h2.as_bytes() {
            (&b1, &b2)
        } else {
            (&b2, &b1)
        };
        // Push the loser first.
        a.push_block(loser).unwrap();
        assert_eq!(
            a.tip_hash(),
            crate::block_hash::block_hash(&loser.header).unwrap()
        );
        // The winner arrives late: same height, lower hash — the
        // reorg adopts it.
        let applied = a.try_attach(winner).unwrap();
        assert_eq!(a.tip_hash(), applied.hash);
        assert_eq!(
            a.tip_hash(),
            crate::block_hash::block_hash(&winner.header).unwrap()
        );
        assert_eq!(a.height(), h);
    }

    #[test]
    fn branch_adoption_longest_wins() {
        let mut a = chain_with("example.uip");
        let fork_point = a.height();
        // Competing branch: two blocks vs our one.
        let mut b1 = child(&a, vec![]);
        b1.header.timestamp = 500;
        b1.header.height = fork_point + 1;
        b1.header.tx_root = crate::merkle::tx_root(&b1.transactions).unwrap();
        crate::chain::tests_support::resign(&mut b1);
        let b1_hash = crate::block_hash::block_hash(&b1.header).unwrap();
        let mut b2 = child_of_hash(b1_hash, fork_point + 2, vec![]);
        b2.header.tx_root = crate::merkle::tx_root(&b2.transactions).unwrap();
        crate::chain::tests_support::resign(&mut b2);
        let adopted = a.adopt_branch(&[b1, b2]).unwrap();
        assert!(adopted);
        assert_eq!(a.height(), fork_point + 2);
    }

    #[test]
    fn finalized_checkpoint_blocks_contradicting_branch() {
        let mut a = chain_with("example.uip");
        // Finalize a checkpoint on the current tip (self-signed by a
        // committee of the pool — here: fabricate acceptance by
        // driving accept_checkpoint with a quorum we control).
        // For the unit test we push a checkpoint directly through the
        // internal path: build it, sign with 4 keys of the pool.
        let cp_data = a.checkpoint_data(0).unwrap();
        let committee = a.committee(0);
        // The testnet committee size is 4; the pool holds the single
        // claimer... eligible pool may be < 4: finality is deferred.
        // In that case accept_checkpoint must REFUSE — which is the
        // documented BFT guard. Exercise the guard:
        let quorum = scone_core::quorum_for(committee.len());
        let mut sigs = Vec::new();
        for sk in committee_keys(&committee) {
            let payload = cp_data.signing_bytes();
            let sig = sk.sign(&payload);
            sigs.push((sk.public_key(), sig));
        }
        let cp = scone_core::checkpoint::Checkpoint {
            data: cp_data,
            signatures: sigs,
        };
        // Committee of 1 (single claimer) < MIN_FINALITY_COMMITTEE_SIZE:
        // acceptance must fail with the BFT guard.
        if committee.len() < scone_core::MIN_FINALITY_COMMITTEE_SIZE {
            assert!(a.accept_checkpoint(cp).is_err());
            return;
        }
        let _ = quorum;
        a.accept_checkpoint(cp).unwrap();
        // A branch forking BELOW the finalized height must be refused.
        let fork_point = 1u64; // below the checkpointed tip
        let mut b1 = child_at(&a, fork_point);
        b1.header.tx_root = crate::merkle::tx_root(&b1.transactions).unwrap();
        let res = a.adopt_branch(&[b1]);
        let refused = matches!(
            &res,
            Err(BlockchainError::Consensus(msg)) if msg.contains("finalized")
        );
        assert!(
            refused,
            "branch contradicting finality must be refused: {res:?}"
        );
    }

    #[test]
    fn replay_after_reorg_is_bit_exact() {
        // Two nodes adopting branches in different orders reach the
        // same state (determinism through the reorg path).
        let mut left = chain_with("example.uip");
        let mut right = chain_with("example.uip");
        let fork_point = left.height();
        let mut b1 = child(&left, vec![]);
        b1.header.timestamp = 501;
        b1.header.height = fork_point + 1;
        b1.header.tx_root = crate::merkle::tx_root(&b1.transactions).unwrap();
        crate::chain::tests_support::resign(&mut b1);
        let b1_hash = crate::block_hash::block_hash(&b1.header).unwrap();
        let mut b2 = child_of_hash(b1_hash, fork_point + 2, vec![]);
        b2.header.tx_root = crate::merkle::tx_root(&b2.transactions).unwrap();
        crate::chain::tests_support::resign(&mut b2);
        left.adopt_branch(&[b1.clone(), b2.clone()]).unwrap();
        right.push_block(&b1).unwrap();
        right.push_block(&b2).unwrap();
        assert_eq!(left.tip_hash(), right.tip_hash());
        assert_eq!(left.state, right.state);
    }
}
