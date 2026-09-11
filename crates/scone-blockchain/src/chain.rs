//! Canonical in-memory chain and block validation.

use std::collections::HashMap;

use scone_protocol::limits::MAX_TXS_PER_BLOCK;
use scone_protocol::{Block, BlockHash, PROTOCOL_VERSION};

use scone_core::{DomainId, NetworkParams, TESTNET};

use crate::txid::{TxId, transaction_id};

/// Anti-replay window (blocks), ported from the .bak
/// (`REPLAY_WINDOW_BLOCKS`): a transaction id stays protected against
/// re-inclusion for this many blocks after its inclusion, then
/// leaves the index.
///
/// The rule is a **pure function of the canonical chain** (inclusion
/// height only): a live node (pruned index) and a node replaying the
/// same blocks hold identical indices at every height and take
/// identical decisions. RAM is bounded by `window × txs/block`,
/// independent of the chain's lifetime. A re-inclusion after the
/// window remains subject to the domain rules (duplicate / owner /
/// expiry) and requires the original signed bytes: the effect is the
/// re-application of a transaction the signer consented to, never a
/// forgery.
pub const REPLAY_WINDOW_BLOCKS: u64 = 256;

/// Bounded RAM window of canonical blocks (M7a, ported from the
/// .bak's `HISTORY_KEEP = 512`): the chain keeps at most this many
/// recent blocks **above the finality floor** in RAM. A block whose
/// height is strictly below BOTH `tip_height - RAM_WINDOW_BLOCKS + 1`
/// and the last finalized checkpoint's height is evicted — it can
/// never be needed again, because a reorg requires a branch that
/// beats the canonical chain under the fork choice, and any branch
/// contradicting a finalized checkpoint is refused outright.
///
/// Blocks at or above the finality floor are NEVER evicted, whatever
/// the window says (a reorg through them stays possible until
/// finality locks them). Consequence: before the first finalized
/// checkpoint (bootstrap), NOTHING is ever evicted — bounded RAM
/// starts with finality. The node store (`scone-storage`) serves the
/// evicted heights; [`Blockchain::block`] returns [`None`] and
/// [`Blockchain::block_result`] returns
/// [`BlockchainError::BlockPruned`] for them.
pub const RAM_WINDOW_BLOCKS: u64 = 512;

use crate::block_hash::block_hash;
use crate::consensus::{Consensus, PermissiveConsensus};
use crate::error::{BlockchainError, Result};
use crate::genesis::genesis_of;
use crate::merkle::tx_root;
use crate::state::ChainState;
use crate::validate::validate_transaction;

/// An in-memory canonical blockchain: genesis + accepted blocks, with
/// the authoritative [`ChainState`].
///
/// Validation is total: every pushed block has its Merkle root and hash
/// **recomputed** (values provided by a peer are never trusted), its
/// parent checked against the canonical tip, and each transaction
/// validated (core rules, consensus hooks, state rules) then applied in
/// block order. Nothing ever panics on hostile input, and state
/// application is atomic per block: if any transaction fails, the
/// pre-push state is preserved.
///
/// Fork handling (minimum, see `/docs/technical/blockchain.md`): a block whose
/// parent was never seen is rejected with
/// [`BlockchainError::UnknownParent`]; a block building on a known
/// non-tip block is rejected with [`BlockchainError::ParentNotTip`]. No
/// received block is ever treated as canonical before passing full
/// validation. Real fork choice belongs to the future consensus.
#[derive(Debug)]
pub struct Blockchain<C: Consensus = PermissiveConsensus> {
    /// Height of the oldest non-genesis block held in RAM. `0` on a
    /// young live chain (`canonical` is dense: index == height,
    /// genesis at index 0). Advanced by the RAM window eviction (M7a,
    /// see [`RAM_WINDOW_BLOCKS`]) and by [`Blockchain::restore`]:
    /// historical heights below `base_height` are served from the
    /// node store — [`block`](Self::block) returns `None` and
    /// [`block_result`](Self::block_result) returns
    /// [`BlockchainError::BlockPruned`] for them.
    pub(crate) base_height: u64,
    /// Canonical blocks held in RAM: dense from genesis on a young
    /// chain (`canonical[0]` is genesis, index == height). Once the
    /// window slides (M7a) or the chain is restored, the layout is
    /// `[genesis, window base, …, tip]` — `canonical[1 + k]` is the
    /// block at height `base_height + k`.
    pub(crate) canonical: Vec<Block>,
    /// Hash of every accepted block **still in the RAM window**, by
    /// height (parent classification for fork detection). Bounded
    /// with the window (M7a): evicted heights leave the index, so a
    /// fork building on a pruned parent classifies as
    /// [`BlockchainError::UnknownParent`] — the relay falls back to
    /// loading it from the node store or to a full sync.
    pub(crate) known_hashes: HashMap<u64, BlockHash>,
    pub(crate) tip: BlockHash,
    /// The network this chain belongs to (M8b): its genesis, its
    /// PoW parameters, the only network id its transactions may carry.
    pub(crate) network: NetworkParams,
    pub(crate) state: ChainState,
    consensus: C,
    /// TXIDs of the transactions included **within the last
    /// [`REPLAY_WINDOW_BLOCKS`] blocks** (anti-replay window ported
    /// from the .bak: a transaction never enters the chain twice).
    /// Maps TXID → inclusion height, pruned deterministically at each
    /// push (pure function of the canonical chain — two nodes
    /// replaying the same chain hold the same index at every height).
    included: HashMap<TxId, u64>,
    /// Finalized checkpoints (chained, windowed — M3 of the .bak
    /// port). The last one is the PoS base.
    pub(crate) checkpoints: Vec<scone_core::checkpoint::Checkpoint>,
    /// Frozen PoS base (last finalized checkpoint + eligibility
    /// pool). None: bootstrap.
    pub(crate) finalized: Option<crate::finality::FinalizedBase>,
}

/// What `push_block` actually changed (M8b): the accepted block's
/// hash plus the state side-effects the caller must persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedBlock {
    /// Recomputed hash of the accepted block (new canonical tip).
    pub hash: BlockHash,
    /// Domains removed by the deterministic expiry-GC while applying
    /// the block (evaluated at the parent block timestamp). The
    /// storage layer deletes their persisted states in the same
    /// atomic append — without this, a restart would reload expired
    /// registrations until the next block lands.
    pub gc_removed_domains: Vec<DomainId>,
}

impl Blockchain<PermissiveConsensus> {
    /// New chain at the **testnet** genesis with the permissive
    /// placeholder consensus (development default, M8b).
    #[must_use]
    pub fn new() -> Self {
        Self::with_consensus(PermissiveConsensus)
    }

    /// New chain at the genesis of `network` (M8b). The genesis hash
    /// embeds the network id: chains of different networks can never
    /// share a block.
    #[must_use]
    pub fn for_network(network: NetworkParams) -> Self {
        Self::with_consensus_for_network(PermissiveConsensus, network)
    }

    /// The network this chain belongs to (M8b).
    #[must_use]
    pub fn network(&self) -> NetworkParams {
        self.network
    }
}

impl Default for Blockchain<PermissiveConsensus> {
    fn default() -> Self {
        Self::new()
    }
}

impl Blockchain<PermissiveConsensus> {
    /// Restores a chain from persistent storage **without replaying**
    /// blocks (storage integration; see `scone-storage`).
    ///
    /// `tip_block` is the stored canonical tip (already validated when
    /// it was accepted; only its height is re-checked against
    /// `tip_height`), `tip` its recomputed hash, `state` the persisted
    /// domain states. Memory-bounded by design: only genesis and the
    /// tip block are held in RAM — historical blocks stay in the store.
    ///
    /// # Panics
    ///
    /// Panics if `tip_block.header.height != tip_height` — caller
    /// error, not untrusted data (storage bytes are checked before
    /// this call).
    #[must_use]
    pub fn restore(tip_height: u64, tip: BlockHash, tip_block: Block, state: ChainState) -> Self {
        assert_eq!(
            tip_block.header.height, tip_height,
            "restore: tip block height mismatch"
        );
        let network = state.network();
        let genesis_block = genesis_of(&network);
        let genesis_h = crate::block_hash::block_hash(&genesis_block.header)
            .expect("genesis header is valid by construction");
        Self {
            base_height: tip_height,
            canonical: vec![genesis_block, tip_block],
            known_hashes: HashMap::from([(0, genesis_h), (tip_height, tip)]),
            tip,
            network,
            state,
            consensus: PermissiveConsensus,
            included: HashMap::new(),
            checkpoints: Vec::new(),
            finalized: None,
        }
    }
}

impl<C: Consensus> Blockchain<C> {
    /// New chain at the testnet genesis with a custom consensus.
    #[must_use]
    pub fn with_consensus(consensus: C) -> Self {
        Self::with_consensus_for_network(consensus, TESTNET)
    }

    /// New chain at the genesis of `network` with a custom consensus
    /// (M8b).
    #[must_use]
    pub fn with_consensus_for_network(consensus: C, network: NetworkParams) -> Self {
        let hash = crate::block_hash::block_hash(&genesis_of(&network).header)
            .expect("genesis header is valid by construction");
        Self {
            base_height: 0,
            canonical: vec![genesis_of(&network)],
            known_hashes: HashMap::from([(0, hash)]),
            tip: hash,
            network,
            state: ChainState::for_network(network),
            consensus,
            included: HashMap::new(),
            checkpoints: Vec::new(),
            finalized: None,
        }
    }

    /// The genesis block.
    #[must_use]
    pub fn genesis(&self) -> &Block {
        &self.canonical[0]
    }

    /// The current canonical tip block.
    #[must_use]
    pub fn tip(&self) -> &Block {
        self.canonical.last().expect("chain always has genesis")
    }

    /// Hash of the current canonical tip.
    #[must_use]
    pub fn tip_hash(&self) -> BlockHash {
        self.tip
    }

    /// Height of the current tip (genesis = 0).
    #[must_use]
    pub fn height(&self) -> u64 {
        self.tip().header.height
    }

    /// Canonical block at `height`, if it exists — O(1) window
    /// lookup.
    ///
    /// Blocks of the current window are in RAM; heights below
    /// [`RAM_WINDOW_BLOCKS`]-eviction or a
    /// [`Blockchain::restore`]d chain's history are not — they are
    /// served from the node store, and this returns [`None`] for
    /// them (use [`Blockchain::block_result`] for the typed
    /// [`BlockchainError::BlockPruned`] distinction).
    #[must_use]
    pub fn block(&self, height: u64) -> Option<&Block> {
        if height == 0 {
            // Genesis is always in RAM (`canonical[0]` on a live
            // chain, prepended by `restore`).
            return self.canonical.first().filter(|g| g.header.height == 0);
        }
        // Heights below `base_height` (advanced by the RAM window
        // eviction, M7a, or by restore) are not in RAM. The genesis
        // slot at index 0 shifts the window by one; a young chain
        // (`base_height == 0`) is dense (index == height).
        let offset: usize = height.checked_sub(self.base_height)?.try_into().ok()?;
        let index = if self.base_height == 0 {
            offset
        } else {
            offset + 1
        };
        self.canonical
            .get(index)
            .filter(|b| b.header.height == height)
    }

    /// [`Blockchain::block`] with a typed failure (M7a):
    /// [`BlockchainError::BlockPruned`] when there is no canonical
    /// block at `height` in RAM — either it was evicted by the
    /// bounded window (below the finality floor; the node store
    /// serves it) or the height is beyond the tip (callers check
    /// [`Blockchain::height`] first).
    ///
    /// # Errors
    ///
    /// [`BlockchainError::BlockPruned`] — never panics.
    pub fn block_result(&self, height: u64) -> Result<&Block> {
        self.block(height)
            .ok_or(BlockchainError::BlockPruned { height })
    }

    /// Authoritative state after all applied blocks.
    #[must_use]
    pub fn state(&self) -> &ChainState {
        &self.state
    }

    /// Whether `id` was included in a canonical block **within the
    /// anti-replay window** ([`REPLAY_WINDOW_BLOCKS`]). A transaction
    /// must never enter the chain (nor a mempool) twice while its id
    /// is in the window (ported from the .bak).
    #[must_use]
    pub fn is_tx_included(&self, id: &TxId) -> bool {
        self.included.contains_key(id)
    }

    /// Rebuilds the anti-replay TXID index after a restore (M8).
    ///
    /// A restored chain starts with an empty `included` map — the
    /// index is a pure function of the canonical chain, never
    /// persisted as such. The storage layer reconstructs it at boot
    /// by re-scanning the persisted window tail: every transaction
    /// of the last [`REPLAY_WINDOW_BLOCKS`] blocks (at most — fewer
    /// on a young chain) is re-inserted at its **original inclusion
    /// height**, exactly as `push_block` would have recorded it.
    /// A node that reboots and a node that never stopped therefore
    /// hold identical indices and reject the same replays
    /// (deterministic, same decisions at every height).
    ///
    /// Entries at or below `tip_height - REPLAY_WINDOW_BLOCKS` are
    /// pruned by the same rule as `push_block` (`h > cutoff`):
    /// callers feeding the full history converge too, and a caller
    /// passing only the window tail pays no pruning at all. An entry
    /// whose height exceeds the current tip is ignored (it cannot
    /// exist on the canonical chain — caller error, not untrusted
    /// data: heights come from the node store, already validated).
    ///
    /// No direct field access: this is the single sanctioned way to
    /// mutate the index outside `push_block`.
    pub fn rebuild_replay_index<I: Iterator<Item = (TxId, u64)>>(&mut self, entries: I) {
        let tip = self.height();
        let cutoff = tip.saturating_sub(REPLAY_WINDOW_BLOCKS);
        for (id, height) in entries {
            if height > tip || height <= cutoff {
                continue;
            }
            self.included.insert(id, height);
        }
    }

    /// Number of TXIDs currently held in the anti-replay index
    /// (diagnostics and boot-reconstruction tests — the live bound
    /// is `REPLAY_WINDOW_BLOCKS × txs/block`).
    #[must_use]
    pub fn replay_index_len(&self) -> usize {
        self.included.len()
    }

    /// Hash of the canonical block at `height`, if it is in the RAM
    /// window (fork classification, M7a: evicted heights answer
    /// `None` — the relay then goes through the node store).
    #[must_use]
    pub fn block_hash_at(&self, height: u64) -> Option<BlockHash> {
        self.known_hashes.get(&height).copied()
    }

    /// Owned copy of the known-hash index (reorg swap).
    pub(crate) fn known_hashes_vec(&self) -> HashMap<u64, BlockHash> {
        self.known_hashes.clone()
    }

    /// Replaces the known-hash index (reorg swap).
    pub(crate) fn replace_hashes(&mut self, hashes: HashMap<u64, BlockHash>) {
        self.known_hashes = hashes;
    }

    /// Finality floor (M7a): the height of the last finalized
    /// checkpoint. Canonical blocks at or above it are NEVER evicted
    /// from the RAM window — a reorg through them stays possible
    /// until finality locks them. `None` before the first finalized
    /// checkpoint (bootstrap: nothing is ever evicted).
    #[must_use]
    pub fn finality_floor(&self) -> Option<u64> {
        self.checkpoints.last().map(|cp| cp.data.height)
    }

    /// Classifies a parent-hash miss (M7a): when the PARENT's height
    /// (`child_height - 1`) is below `base_height`, the parent was
    /// evicted from the RAM window — the caller (relay) must reload
    /// it from the node store or fall back to a full sync, so the
    /// miss is typed [`BlockchainError::BlockPruned`]. Anything else
    /// is a parent this chain has never seen (genesis, height 0, is
    /// always in RAM and never reported pruned).
    pub(crate) fn classify_parent_miss(&self, child_height: u64) -> BlockchainError {
        let parent_height = child_height.saturating_sub(1);
        if parent_height >= 1 && parent_height < self.base_height {
            BlockchainError::BlockPruned {
                height: parent_height,
            }
        } else {
            BlockchainError::UnknownParent
        }
    }

    /// Evicts canonical blocks below the RAM window (M7a). A block
    /// leaves RAM only when BOTH conditions hold:
    ///
    /// 1. its height `< tip_height - RAM_WINDOW_BLOCKS + 1` (outside
    ///    the window);
    /// 2. its height is strictly below the finality floor (the last
    ///    finalized checkpoint) — a reorg above the floor is always
    ///    possible, so those blocks must stay reachable.
    ///
    /// Before the first finalized checkpoint, NOTHING is evicted
    /// (bounded RAM starts with finality). The eviction is REAL:
    /// blocks, their hash index entries and their Merkle/root data
    /// are dropped (the `Vec::drain` releases the memory; the node
    /// store owns the durable copies). Genesis never leaves RAM.
    fn evict_below_window(&mut self) {
        let Some(floor) = self.finality_floor() else {
            return; // bootstrap: no finality, no eviction
        };
        let tip_height = self.height();
        // Invariant: a finalized checkpoint height is ≤ tip.
        let window_start = tip_height.saturating_sub(RAM_WINDOW_BLOCKS - 1);
        // Evict strictly below min(window_start, floor): the floor
        // itself and everything above it survive even outside the
        // window (a reorg can still require them).
        let new_base = window_start.min(floor);
        if new_base <= self.base_height {
            return;
        }
        // Blocks at heights base_height..new_base-1 leave the Vec.
        // On a never-evicted live chain (`base_height == 0`) the
        // layout is dense with genesis at index 0 == height 0, so
        // only `new_base - 1` entries (heights 1..new_base-1) are
        // drained; afterwards the layout is [genesis, base..tip].
        let n = if self.base_height == 0 {
            (new_base - 1) as usize
        } else {
            (new_base - self.base_height) as usize
        };
        debug_assert!(n < self.canonical.len());
        self.canonical.drain(1..1 + n);
        // Genesis hash (key 0) never leaves the index.
        for h in self.base_height.max(1)..new_base {
            self.known_hashes.remove(&h);
        }
        self.base_height = new_base;
    }

    /// Validates `block` and, if fully valid, appends it as the new
    /// canonical tip, applying its transactions to the state.
    ///
    /// All commitments are recomputed from scratch. On any error the
    /// chain is left exactly as before.
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub fn push_block(&mut self, block: &Block) -> Result<BlockHash> {
        self.push_block_with_gc(block).map(|outcome| outcome.hash)
    }

    /// [`Blockchain::push_block`] returning the full application
    /// outcome (M8b): the block hash **and the domains the
    /// deterministic expiry-GC removed** while applying this block —
    /// the caller persists those removals so a restart can never
    /// resurrect an expired registration (see
    /// `scone-storage::store_block_with_removals`).
    ///
    /// # Errors
    ///
    /// See [`BlockchainError`]; never panics.
    pub fn push_block_with_gc(&mut self, block: &Block) -> Result<AppliedBlock> {
        let header = &block.header;

        // Parent: must extend the canonical tip.
        if header.prev_hash != self.tip {
            return Err(
                if self.known_hashes.values().any(|h| *h == header.prev_hash) {
                    BlockchainError::ParentNotTip
                } else {
                    // M7a: a parent height that left the RAM window is a
                    // typed miss (the node store serves it), not a plain
                    // unknown parent.
                    self.classify_parent_miss(header.height)
                },
            );
        }
        // Height: strictly parent + 1.
        let expected_height =
            self.height()
                .checked_add(1)
                .ok_or(BlockchainError::InvalidHeight {
                    expected: u64::MAX,
                    got: header.height,
                })?;
        if header.height != expected_height {
            return Err(BlockchainError::InvalidHeight {
                expected: expected_height,
                got: header.height,
            });
        }
        // Version: exactly the local protocol version. Lower (v1,
        // pre-signature format) is a different, incompatible block
        // format; higher is unknown.
        if header.version != PROTOCOL_VERSION {
            return Err(BlockchainError::InvalidVersion(header.version));
        }
        // Bounded transaction list.
        if block.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(BlockchainError::TooManyTransactions(
                block.transactions.len(),
            ));
        }
        // Recompute the Merkle root over the ordered transactions:
        // header.tx_root is never trusted.
        if tx_root(&block.transactions)? != header.tx_root {
            return Err(BlockchainError::MerkleMismatch);
        }

        // Anti-replay (ported from the .bak): a transaction already
        // included in the chain (within the window) never re-enters
        // it. Deterministic — the index is derivable from the blocks,
        // so every node replaying the same chain decides identically.
        for tx in &block.transactions {
            if let Ok(id) = transaction_id(tx)
                && self.included.contains_key(&id)
            {
                return Err(BlockchainError::TxReplay);
            }
        }

        let hash = block_hash(header)?;

        // Consensus hooks (PoW etc.).
        self.consensus.validate_header(header)?;
        // M5 (.bak port): the block must be SIGNED by an allowed
        // producer — the PoS authority is enforced here, at
        // application time, on every node (recomputed hash, never a
        // provided value). The genesis block (height 0, empty
        // consensus payload) is structural and never lands here.
        if header.height > 0 {
            let payload = crate::producer::decode_producer_payload(&header.consensus).ok_or(
                BlockchainError::InvalidProducer(
                    "consensus payload is not a signed producer payload".into(),
                ),
            )?;
            let signing_hash = crate::producer::producer_signing_hash(header).ok_or(
                BlockchainError::InvalidProducer("header is not encodable".into()),
            )?;
            if !crate::producer::verify_block_producer(&payload, &signing_hash) {
                return Err(BlockchainError::InvalidProducer(
                    "producer signature does not verify over the block hash".into(),
                ));
            }
            let allowed = self.allowed_producers(header.timestamp);
            // Empty allowed set = bootstrap of a fresh chain (no live
            // domain yet): production is open — otherwise the first
            // REGISTER would be impossible. A non-empty set is strict.
            if !allowed.is_empty() && !allowed.contains(&payload.producer) {
                return Err(BlockchainError::InvalidProducer(
                    "producer is not in the allowed set (not an anchor, not an owner of a live domain)".into(),
                ));
            }
        }

        // Transactions: cryptographic validation (owner/key binding
        // recomputed, signature over the recomputed canonical
        // payload), consensus hooks and deterministic application.
        // Atomicity per block is provided by an undo journal (one
        // entry per applied transaction, O(txs per block)) instead of
        // cloning the whole state per block: on any failure below,
        // rollback restores the exact pre-push state.
        // M8b: expirations are evaluated against the PARENT block
        // timestamp (committed in the canonical parent header —
        // deterministic, unlike a wall clock), before the block's own
        // transactions apply.
        let parent_time = self.tip().header.timestamp;
        let mut journal = crate::state::UndoLog::default();
        let gc_removed_domains = self.state.gc_expired_journaled(parent_time, &mut journal);
        let apply = (|| {
            for tx in &block.transactions {
                validate_transaction(tx)?;
                self.consensus.validate_tx(tx)?;
                self.state
                    .apply_journaled_at(tx, parent_time, &mut journal)?;
            }
            Ok(())
        })();

        match apply {
            Ok(()) => {}
            Err(e) => {
                self.state.rollback(journal);
                return Err(e);
            }
        }

        self.known_hashes.insert(header.height, hash);
        self.canonical.push(block.clone());
        self.tip = hash;
        // M7a: slide the bounded RAM window. Real eviction — blocks
        // below both the window and the finality floor leave RAM
        // (and the hash index) immediately; the node store owns the
        // durable copies.
        self.evict_below_window();
        // Anti-replay index: record each transaction's inclusion
        // height, then prune deterministically — beyond the window the
        // TXID leaves the index (identical decision on any node that
        // replays the same chain; ported semantics from the .bak:
        // entry = inclusion height, `retain(h > cutoff)`).
        for tx in &block.transactions {
            if let Ok(id) = transaction_id(tx) {
                self.included.insert(id, header.height);
            }
        }
        let cutoff = header.height.saturating_sub(REPLAY_WINDOW_BLOCKS);
        if header.height > REPLAY_WINDOW_BLOCKS {
            self.included.retain(|_, h| *h > cutoff);
        }
        Ok(AppliedBlock {
            hash,
            gc_removed_domains,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) use super::tests::{
        child, claim_open_uip, producer_key, register_domain_tx, resign, update_domain_tx,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BlockchainError;
    use crate::genesis::{genesis, genesis_hash};
    use scone_core::{
        DomainId, DomainName, Proof, RecordHash, RegisterDomain, RegisterTld, TldName, Transaction,
        UpdateDomain,
    };
    use scone_crypto::{Signature, SigningKey};
    use scone_protocol::codec::{decode_complete, encode_to_vec};
    use scone_protocol::{BlockHeader, MerkleRoot};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    /// Re-signs a transaction over its canonical signing payload.
    fn sign(unsigned: Transaction, sk: &SigningKey) -> Transaction {
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        match unsigned {
            Transaction::RegisterDomain(mut r) => {
                r.signature = sk.sign(&payload);
                Transaction::RegisterDomain(r)
            }
            Transaction::UpdateDomain(mut u) => {
                u.signature = sk.sign(&payload);
                Transaction::UpdateDomain(u)
            }
            Transaction::RegisterTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::RegisterTld(t)
            }
            Transaction::TransferTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::TransferTld(t)
            }
            Transaction::RevokeTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::RevokeTld(t)
            }
            Transaction::SetTldOpen(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::SetTldOpen(t)
            }
            Transaction::AssignDomain(mut a) => {
                a.signature = sk.sign(&payload);
                Transaction::AssignDomain(a)
            }
            Transaction::RenewDomain(mut r) => {
                r.signature = sk.sign(&payload);
                Transaction::RenewDomain(r)
            }
            Transaction::Slash(mut s) => {
                s.signature = sk.sign(&payload);
                Transaction::Slash(s)
            }
        }
    }

    fn unsigned_register_domain(name: &str, seed: u8) -> Transaction {
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).unwrap(),
            1,
            mined_proof(name, "domain"),
            SigningKey::from_bytes([seed; 32]).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    pub(crate) fn register_domain_tx(name: &str, seed: u8) -> Transaction {
        sign(
            unsigned_register_domain(name, seed),
            &SigningKey::from_bytes([seed; 32]),
        )
    }

    fn unsigned_update(name: &str, seed: u8, sequence: u64) -> Transaction {
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            domain_id(name),
            sequence,
            RecordHash::from_bytes([sequence as u8; 32]),
            SigningKey::from_bytes([seed; 32]).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    pub(crate) fn update_domain_tx(name: &str, seed: u8, sequence: u64) -> Transaction {
        sign(
            unsigned_update(name, seed, sequence),
            &SigningKey::from_bytes([seed; 32]),
        )
    }

    /// Mines a registration proof at the testnet difficulty for
    /// `kind` ("tld" or "domain") over `name`.
    pub(crate) fn mined_proof(name: &str, kind: &str) -> Proof {
        let (prefix, difficulty) = if kind == "tld" {
            (
                scone_core::id::TLD_ID_VERSION,
                scone_core::TESTNET.tld_pow_difficulty,
            )
        } else {
            (
                scone_core::id::DOMAIN_ID_VERSION,
                scone_core::TESTNET.domain_pow_difficulty,
            )
        };
        let mut challenge = Vec::with_capacity(prefix.len() + name.len());
        challenge.extend_from_slice(prefix);
        challenge.extend_from_slice(name.as_bytes());
        let checked = scone_core::pow::mine(scone_core::TESTNET.network_id, &challenge, difficulty);
        Proof::from_bytes(scone_core::pow::encode_proof(&checked))
    }

    pub(crate) fn register_tld_tx(tld: &str, seed: u8) -> Transaction {
        sign(
            Transaction::RegisterTld(RegisterTld::register_tld_signed(
                TldName::new(tld).unwrap(),
                1,
                mined_proof(tld, "tld"),
                SigningKey::from_bytes([seed; 32]).public_key(),
                Signature::from_bytes([0; 64]),
            )),
            &SigningKey::from_bytes([seed; 32]),
        )
    }

    /// Deterministic test producer key (M5: blocks must be signed).
    /// Test producer key = the `uip` TLD owner's key (`[1; 32]`,
    /// see `claim_open_uip`): after a claim the producer pool is
    /// non-empty and production is restricted to live-domain owners,
    /// so test blocks must be signed by an owner.
    pub(crate) fn producer_key() -> SigningKey {
        SigningKey::from_bytes([1; 32])
    }

    pub(crate) fn make_block(prev: BlockHash, height: u64, txs: Vec<Transaction>) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height,
                prev_hash: prev,
                tx_root: tx_root(&txs).unwrap(),
                timestamp: height, // deterministic placeholder
                consensus: Vec::new(),
            },
            transactions: txs,
        };
        resign(&mut block);
        block
    }

    /// Re-signs a test block after its header was mutated (M5: the
    /// producer payload covers every header field but `consensus`).
    pub(crate) fn resign(block: &mut Block) {
        let sh = crate::producer::producer_signing_hash(&block.header).unwrap();
        let sig = crate::producer::sign_block_hash(&producer_key(), &sh);
        block.header.consensus =
            crate::producer::encode_producer_payload(&producer_key().public_key(), &sig);
    }

    pub(crate) fn child<C: crate::Consensus>(
        chain: &Blockchain<C>,
        txs: Vec<Transaction>,
    ) -> Block {
        make_block(chain.tip_hash(), chain.height() + 1, txs)
    }

    pub(crate) fn set_open_tx(tld: &str, seed: u8, open: bool) -> Transaction {
        sign(
            Transaction::SetTldOpen(scone_core::SetTldOpen::set_tld_open_signed(
                scone_core::TldId::from_tld(&TldName::new(tld).unwrap()),
                open,
                SigningKey::from_bytes([seed; 32]).public_key(),
                Signature::from_bytes([0; 64]),
            )),
            &SigningKey::from_bytes([seed; 32]),
        )
    }

    /// Claims `uip` (PoW) and opens it for self-registration: the
    /// canonical precondition of every domain fixture (M8b).
    pub(crate) fn claim_open_uip(chain: &mut Blockchain, seed: u8) {
        chain
            .push_block(&child(
                chain,
                vec![register_tld_tx("uip", seed), set_open_tx("uip", seed, true)],
            ))
            .unwrap();
    }

    #[test]
    fn new_chain_is_at_genesis() {
        let chain = Blockchain::new();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.tip_hash(), genesis_hash());
        assert_eq!(chain.tip(), &genesis());
        assert_eq!(chain.block(0), Some(&genesis()));
        assert!(chain.block(1).is_none());
        assert!(chain.state().is_empty());
    }

    #[test]
    fn genesis_identical_across_chains() {
        assert_eq!(Blockchain::new().tip_hash(), Blockchain::new().tip_hash());
        assert_eq!(Blockchain::new().genesis(), &genesis());
    }

    #[test]
    fn genesis_cannot_be_repushed() {
        let mut chain = Blockchain::new();
        // prev_hash of genesis is all zeros, not the tip hash.
        assert_eq!(
            chain.push_block(&genesis()),
            Err(BlockchainError::UnknownParent)
        );
    }

    #[test]
    fn valid_blocks_extend_the_chain() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let b1 = child(&chain, vec![register_domain_tx("example.uip", 1)]);
        let h1 = chain.push_block(&b1).unwrap();
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.tip_hash(), h1);
        assert_eq!(chain.tip(), &b1);

        let b2 = child(&chain, vec![update_domain_tx("example.uip", 1, 1)]);
        let h2 = chain.push_block(&b2).unwrap();
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip_hash(), h2);
        assert_eq!(chain.block(2), Some(&b1));
        assert_eq!(chain.block(3), Some(&b2));
    }

    #[test]
    fn register_then_update_reaches_the_state() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        chain
            .push_block(&child(&chain, vec![update_domain_tx("example.uip", 1, 1)]))
            .unwrap();

        let domain = chain.state().domain(&domain_id("example.uip")).unwrap();
        let sk = SigningKey::from_bytes([1; 32]);
        assert_eq!(
            domain.owner,
            crate::validate::owner_from_public_key(&sk.public_key())
        );
        assert_eq!(domain.sequence, 1);
        assert_eq!(domain.record_hash, Some(RecordHash::from_bytes([1; 32])));
    }

    #[test]
    fn register_and_update_in_same_block() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(
                &chain,
                vec![
                    register_domain_tx("example.uip", 1),
                    update_domain_tx("example.uip", 1, 1),
                ],
            ))
            .unwrap();
        let domain = chain.state().domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.sequence, 1);
        assert!(domain.record_hash.is_some());
    }

    #[test]
    fn same_blocks_same_final_state_and_tip() {
        // The same block bytes are pushed on two independent chains:
        // identical final state and tip.
        let mut left = Blockchain::new();
        let mut right = Blockchain::new();

        claim_open_uip(&mut left, 1);
        claim_open_uip(&mut right, 1);
        let b1 = child(
            &left,
            vec![
                register_domain_tx("a.uip", 1),
                register_domain_tx("b.uip", 2),
            ],
        );
        left.push_block(&b1).unwrap();
        right.push_block(&b1).unwrap();

        let b2 = child(&left, vec![update_domain_tx("a.uip", 1, 1)]);
        left.push_block(&b2).unwrap();
        right.push_block(&b2).unwrap();

        assert_eq!(left.tip_hash(), right.tip_hash());
        assert_eq!(left.state(), right.state());
        assert_eq!(left.height(), right.height());
    }

    #[test]
    fn unknown_parent_rejected() {
        let mut chain = Blockchain::new();
        let orphan = make_block(BlockHash::from_bytes([0xab; 32]), 1, vec![]);
        assert_eq!(
            chain.push_block(&orphan),
            Err(BlockchainError::UnknownParent)
        );
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn fork_on_known_non_tip_rejected() {
        let mut chain = Blockchain::new();
        let genesis_hash = chain.tip_hash();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("a.uip", 1)]))
            .unwrap();

        // Competing block on the same (now non-tip) genesis parent.
        let competitor = make_block(genesis_hash, 1, vec![register_domain_tx("b.uip", 1)]);
        assert_eq!(
            chain.push_block(&competitor),
            Err(BlockchainError::ParentNotTip)
        );
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.state().domain(&domain_id("b.uip")), None);
    }

    #[test]
    fn icann_tld_claim_is_rejected_typed() {
        // The ICANN root belongs to the legacy DNS: a claim on com,
        // fr, org… is refused at the state layer, whatever the PoW.
        let mut chain = Blockchain::new();
        assert!(matches!(
            chain.push_block(&child(&chain, vec![register_tld_tx("com", 1)])),
            Err(BlockchainError::IcannTldReserved(t)) if t == "com"
        ));
        // And an unknown-but-free TLD still works (uip is the usual
        // fixture TLD — not in the ICANN list).
        claim_open_uip(&mut chain, 1);
        assert!(chain.state().tld(&tld_id_of("uip")).is_some());
    }

    #[test]
    fn wrong_height_rejected() {
        let mut chain = Blockchain::new();
        for bad_height in [0u64, 2, 3, u64::MAX] {
            let block = make_block(chain.tip_hash(), bad_height, vec![]);
            assert_eq!(
                chain.push_block(&block),
                Err(BlockchainError::InvalidHeight {
                    expected: 1,
                    got: bad_height
                }),
                "height {bad_height}"
            );
        }
        assert_eq!(chain.height(), 0);
    }

    #[test]
    fn invalid_version_rejected() {
        let mut chain = Blockchain::new();
        // 0 and future versions are both rejected: there is exactly
        // one block format.
        for version in [0u32, PROTOCOL_VERSION + 1] {
            let mut block = child(&chain, vec![]);
            block.header.version = version;
            assert_eq!(
                chain.push_block(&block),
                Err(BlockchainError::InvalidVersion(version)),
                "version {version}"
            );
        }
    }

    #[test]
    fn too_many_transactions_rejected() {
        let mut chain = Blockchain::new();
        let txs: Vec<Transaction> = (0..=MAX_TXS_PER_BLOCK)
            .map(|i| register_domain_tx(&format!("d{i}.uip"), 1))
            .collect();
        let mut block = child(&chain, txs);
        block.header.tx_root = tx_root(&block.transactions).unwrap();
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::TooManyTransactions(MAX_TXS_PER_BLOCK + 1))
        );
    }

    #[test]
    fn merkle_mismatch_rejected() {
        let mut chain = Blockchain::new();
        let mut block = child(&chain, vec![register_domain_tx("example.uip", 1)]);
        block.header.tx_root = MerkleRoot::from_bytes([0xcd; 32]);
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::MerkleMismatch)
        );
        assert_eq!(chain.height(), 0);
        assert!(chain.state().is_empty());
    }

    #[test]
    fn merkle_must_cover_block_order() {
        // Same transactions, header claims the root of the reversed
        // list: must be rejected even though both roots are "valid".
        let mut chain = Blockchain::new();
        let txs = vec![
            register_domain_tx("a.uip", 1),
            register_domain_tx("b.uip", 1),
        ];
        let mut block = child(&chain, txs.clone());
        block.header.tx_root = tx_root(&txs.iter().rev().cloned().collect::<Vec<_>>()).unwrap();
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::MerkleMismatch)
        );
    }

    #[test]
    fn invalid_transaction_rejected_chain_unchanged() {
        let mut chain = Blockchain::new();
        // UpdateDomain on an unregistered domain.
        let block = child(&chain, vec![update_domain_tx("example.uip", 1, 1)]);
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::UnknownDomain)
        );
        assert_eq!(chain.height(), 0);
        assert!(chain.state().is_empty());
    }

    #[test]
    fn push_is_atomic_per_block() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let snapshot_state = chain.state().clone();
        let tip = chain.tip_hash();

        let block = child(
            &chain,
            vec![
                register_domain_tx("a.uip", 1),
                register_domain_tx("b.uip", 2),
                register_domain_tx("a.uip", 3), // double register: fails
            ],
        );
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip_hash(), tip);
        assert_eq!(*chain.state(), snapshot_state);
    }

    #[test]
    fn transaction_order_is_significant() {
        // [tld, register, update] applies; [update, register] does not.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(
                &chain,
                vec![
                    register_domain_tx("example.uip", 1),
                    update_domain_tx("example.uip", 1, 1),
                ],
            ))
            .unwrap();

        let mut chain2 = Blockchain::new();
        let block = child(
            &chain2,
            vec![
                update_domain_tx("example.uip", 1, 1),
                register_domain_tx("example.uip", 1),
            ],
        );
        assert_eq!(
            chain2.push_block(&block),
            Err(BlockchainError::UnknownDomain)
        );
    }

    #[test]
    fn tld_then_domain_in_same_block_applies_but_not_the_reverse() {
        // D1 intra-block ordering (M7c): [RegisterTld, RegisterDomain]
        // is valid — the namespace exists when the domain claim applies
        // (transactions apply strictly in block order)…
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(
                &chain,
                vec![
                    register_tld_tx("uip", 1),
                    set_open_tx("uip", 1, true),
                    register_domain_tx("example.uip", 2),
                ],
            ))
            .unwrap();
        assert_eq!(chain.height(), 1);
        assert!(chain.state().domain(&domain_id("example.uip")).is_some());
        assert!(chain.state().tld(&tld_id_of("uip")).is_some());

        // …while [RegisterDomain, RegisterTld] is rejected whole: at
        // the moment the domain claim applies, the TLD does not exist
        // yet, and the undo-log rolls the whole block back.
        let mut other = Blockchain::new();
        let block = child(
            &other,
            vec![
                register_domain_tx("example.uip", 2),
                register_tld_tx("uip", 1),
            ],
        );
        assert_eq!(other.push_block(&block), Err(BlockchainError::UnknownTld));
        assert_eq!(other.height(), 0);
        assert!(other.state().is_empty());
        assert!(other.state().tld_is_empty());
    }

    fn tld_id_of(tld: &str) -> scone_core::TldId {
        scone_core::TldId::from_tld(&scone_core::TldName::new(tld).unwrap())
    }

    #[test]
    fn reversed_transactions_different_block_hash() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let ab = child(
            &chain,
            vec![
                register_domain_tx("a.uip", 1),
                register_domain_tx("b.uip", 1),
            ],
        );
        let ba = child(
            &chain,
            vec![
                register_domain_tx("b.uip", 1),
                register_domain_tx("a.uip", 1),
            ],
        );
        let hash_ab = chain.push_block(&ab.clone()).unwrap();
        let hash_ba = {
            let mut other = Blockchain::new();
            claim_open_uip(&mut other, 1);
            other.push_block(&ba).unwrap();
            other.tip_hash()
        };
        assert_ne!(hash_ab, hash_ba);
    }

    #[test]
    fn long_update_chain() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        for sequence in 1..=50 {
            chain
                .push_block(&child(
                    &chain,
                    vec![update_domain_tx("example.uip", 1, sequence)],
                ))
                .unwrap();
        }
        let domain = chain.state().domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.sequence, 50);
        assert_eq!(chain.height(), 52);
    }

    #[test]
    fn update_from_previous_block_owner_rules_hold() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        // Wrong owner, correct sequence.
        let block = child(&chain, vec![update_domain_tx("example.uip", 2, 1)]);
        assert_eq!(chain.push_block(&block), Err(BlockchainError::NotOwner));
        // Wrong owner and wrong sequence: owner is checked first.
        let block = child(&chain, vec![update_domain_tx("example.uip", 2, 5)]);
        assert_eq!(chain.push_block(&block), Err(BlockchainError::NotOwner));
    }

    #[derive(Debug)]
    struct RejectHeaders;

    impl Consensus for RejectHeaders {
        fn validate_header(&self, _header: &BlockHeader) -> Result<()> {
            Err(BlockchainError::Consensus("header rejected".into()))
        }
        fn validate_tx(&self, _tx: &Transaction) -> Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RejectTx(String);

    impl Consensus for RejectTx {
        fn validate_header(&self, _header: &BlockHeader) -> Result<()> {
            Ok(())
        }
        fn validate_tx(&self, tx: &Transaction) -> Result<()> {
            if matches!(tx, Transaction::RegisterDomain(r) if r.domain_id == domain_id("pow.uip")) {
                return Err(BlockchainError::Consensus(self.0.clone()));
            }
            Ok(())
        }
    }

    #[test]
    fn consensus_header_hook_can_reject() {
        let mut chain = Blockchain::with_consensus(RejectHeaders);
        let block = child(&chain, vec![]);
        assert!(matches!(
            chain.push_block(&block),
            Err(BlockchainError::Consensus(_))
        ));
    }

    #[test]
    fn consensus_tx_hook_can_reject() {
        let mut chain = Blockchain::with_consensus(RejectTx("pow missing".into()));
        let block = child(
            &chain,
            vec![
                register_domain_tx("pow.uip", 1),
                register_domain_tx("other.uip", 1),
            ],
        );
        assert!(matches!(
            chain.push_block(&block),
            Err(BlockchainError::Consensus(msg)) if msg == "pow missing"
        ));
        // The chain still accepts blocks without a `pow.uip` register.
        chain
            .push_block(&child(
                &chain,
                vec![
                    register_tld_tx("uip", 1),
                    set_open_tx("uip", 1, true),
                    register_domain_tx("other.uip", 1),
                ],
            ))
            .unwrap();
    }

    #[test]
    fn chain_unchanged_after_every_rejection_kind() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        let (height, tip, state) = (chain.height(), chain.tip_hash(), chain.state().clone());

        let cases: Vec<Block> = vec![
            make_block(BlockHash::from_bytes([9; 32]), 1, vec![]), // unknown parent
            make_block(chain.tip_hash(), 7, vec![]),               // bad height
            make_block(chain.tip_hash(), 2, vec![update_domain_tx("no.uip", 1, 1)]), // bad tx
        ];
        for block in cases {
            assert!(chain.push_block(&block).is_err());
            assert_eq!(chain.height(), height);
            assert_eq!(chain.tip_hash(), tip);
            assert_eq!(*chain.state(), state);
        }

        let mut bad_root = child(&chain, vec![register_domain_tx("z.uip", 1)]);
        bad_root.header.tx_root = MerkleRoot::from_bytes([1; 32]);
        assert!(chain.push_block(&bad_root).is_err());
        assert_eq!(chain.height(), height);
    }

    #[test]
    fn corrupted_encoded_blocks_never_panic() {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let block = child(&chain, vec![register_domain_tx("example.uip", 1)]);
        let bytes = encode_to_vec(&block).unwrap();
        chain.push_block(&block).unwrap();

        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut corrupted = bytes.clone();
                corrupted[i] ^= mask;
                if let Ok(decoded) = decode_complete::<Block>(&corrupted) {
                    let mut fresh = Blockchain::new();
                    let _ = fresh.push_block(&decoded);
                }
            }
        }
    }

    #[test]
    fn push_block_with_gc_reports_expired_domains() {
        // M8b: the application outcome exposes the GC removals so the
        // storage layer can delete them atomically with the block.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        // claim_open_uip's block has timestamp height(1): register
        // the domain in a block at t=1000.
        chain
            .push_block(
                &child(&chain, vec![register_domain_tx("ghost.uip", 1)])
                    .header
                    .timestamp
                    .checked_add(0)
                    .map(|_| {
                        let mut b = child(&chain, vec![register_domain_tx("ghost.uip", 1)]);
                        b.header.timestamp = 1000;
                        b.header.tx_root = tx_root(&b.transactions).unwrap();
                        resign(&mut b);
                        b
                    })
                    .unwrap(),
            )
            .unwrap();
        let ghost = domain_id("ghost.uip");
        assert!(chain.state().domain(&ghost).is_some());
        // Next block at t past expiry: parent = the t=1000 block, so
        // the GC at parent time does NOT see it yet (one-block lag,
        // documented). Block after that: parent IS past expiry.
        let far = 1000 + 2 * crate::state::DOMAIN_TERM_SECS;
        let mut lag = child(&chain, vec![]);
        lag.header.timestamp = far;
        resign(&mut lag);
        let applied_lag = chain.push_block_with_gc(&lag).unwrap();
        assert!(applied_lag.gc_removed_domains.is_empty());
        let mut after = child(&chain, vec![]);
        after.header.timestamp = far + 1;
        resign(&mut after);
        let applied = chain.push_block_with_gc(&after).unwrap();
        assert_eq!(applied.gc_removed_domains, vec![ghost]);
        assert!(chain.state().domain(&ghost).is_none());
        // Plain push_block keeps its contract: returns the hash.
        let mut empty = child(&chain, vec![]);
        empty.header.timestamp = far + 2;
        resign(&mut empty);
        assert_eq!(chain.push_block(&empty).unwrap(), {
            let mut probe = empty.clone();
            probe.header.timestamp = far + 2;
            crate::block_hash::block_hash(&probe.header).unwrap()
        });
    }

    #[test]
    fn txids_are_stable_across_nodes() {
        // The TxId of a transaction inside a block does not depend on
        // the node computing it (no local clock, no position).
        let tx = register_domain_tx("example.uip", 1);
        let chain = Blockchain::new();
        let block = child(&chain, vec![tx.clone()]);
        assert_eq!(
            transaction_id(&block.transactions[0]).unwrap(),
            transaction_id(&tx).unwrap()
        );
    }

    // ---- Signed-transaction forgery tests (M2) ----

    #[test]
    fn forged_signature_is_rejected() {
        let mut chain = Blockchain::new();
        let mut tx = register_domain_tx("example.uip", 1);
        if let Transaction::RegisterDomain(r) = &mut tx {
            let mut raw = r.signature.to_bytes();
            raw[0] ^= 0x01;
            r.signature = Signature::from_bytes(raw);
        }
        let block = child(&chain, vec![tx]);
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::InvalidSignature)
        );
        assert_eq!(chain.height(), 0);
        assert!(chain.state().is_empty());
    }

    #[test]
    fn signature_by_non_matching_key_is_rejected() {
        // owner/public_key consistent (owner of seed 2), but the
        // signature was produced by the key of seed 1.
        let mut chain = Blockchain::new();
        let mut tx = unsigned_register_domain("example.uip", 2);
        tx = sign(tx, &SigningKey::from_bytes([1; 32]));
        let block = child(&chain, vec![tx]);
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_payload_after_signing_is_rejected() {
        // Sign correctly, then modify a protected field: the
        // recomputed payload no longer matches the signature.
        let mut chain = Blockchain::new();
        let mut tx = register_domain_tx("example.uip", 1);
        if let Transaction::RegisterDomain(r) = &mut tx {
            r.timestamp = 999; // protected by the signature
        }
        let block = child(&chain, vec![tx]);
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::InvalidSignature)
        );
    }

    #[test]
    fn owner_not_derived_from_embedded_key_is_rejected() {
        let tx = unsigned_register_domain("example.uip", 2);
        // Consistent signature by seed 2's key…
        let tx = sign(tx, &SigningKey::from_bytes([2; 32]));
        // …but a forged owner field. The forgery is built at the WIRE
        // level (encode valid → flip the owner bytes → decode): the
        // in-memory API cannot construct an owner-forged RegisterDomain
        // anymore (Encode validates the binding, docs/transactions.md).
        let mut raw = scone_protocol::encode_to_vec(&tx).unwrap();
        // Layout: disc(1) version(1) name(str) domain_id(32) owner(32)…
        let name_len = raw[2] as usize;
        let owner_off = 2 + 1 + name_len + 32;
        raw[owner_off..owner_off + 32].copy_from_slice(
            crate::validate::owner_from_public_key(&SigningKey::from_bytes([9; 32]).public_key())
                .as_bytes(),
        );
        let forged_result = scone_protocol::decode_complete::<Transaction>(&raw);
        assert!(
            forged_result.is_err(),
            "owner-forged RegisterDomain must be rejected on decode (binding owner/pk)"
        );
        // Defense in depth: the chain itself also refuses a forged owner
        // if one ever reaches push (e.g. built in memory then validated).
        // (Covered by `signature_by_non_matching_key_is_rejected` path.)
    }

    #[test]
    fn forged_update_for_someone_elses_domain_is_rejected() {
        // The attacker (seed 2) correctly signs an UpdateDomain but the
        // domain belongs to seed 1: NotOwner at application time.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        let attack = update_domain_tx("example.uip", 2, 1);
        let block = child(&chain, vec![attack]);
        assert_eq!(chain.push_block(&block), Err(BlockchainError::NotOwner));
    }

    #[test]
    fn signed_chain_genesis_block1_block2_deterministic_replay() {
        let assemble = || {
            let sk = SigningKey::from_bytes([5; 32]);
            let mut chain = Blockchain::new();
            claim_open_uip(&mut chain, 1);
            chain
                .push_block(&child(&chain, vec![register_domain_tx("example.uip", 5)]))
                .unwrap();
            let _ = sk;
            chain
                .push_block(&child(&chain, vec![update_domain_tx("example.uip", 5, 1)]))
                .unwrap();
            chain
                .push_block(&child(&chain, vec![update_domain_tx("example.uip", 5, 2)]))
                .unwrap();
            chain
        };
        let left = assemble();
        let right = assemble();
        assert_eq!(left.height(), 4);
        assert_eq!(left.tip_hash(), right.tip_hash());
        assert_eq!(left.state(), right.state());
        let domain = left.state().domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.sequence, 2);
    }

    // ---- restore window (M3) ----

    #[test]
    fn restored_chain_serves_tip_and_genesis_only_from_ram() {
        // Height-8 chain stored, then restored without replay: only
        // genesis (0) and the tip (8) are in RAM; historical heights
        // are the node store's job.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        for height in 2..=8 {
            chain
                .push_block(&child(
                    &chain,
                    vec![update_domain_tx("example.uip", 1, height - 1)],
                ))
                .unwrap();
        }
        assert_eq!(chain.height(), 9);
        let tip_hash = chain.tip_hash();
        let tip_block = chain.block(9).unwrap().clone();

        let restored = Blockchain::restore(9, tip_hash, tip_block.clone(), chain.state().clone());

        assert_eq!(restored.block(9), Some(&tip_block), "tip is in RAM");
        assert_eq!(restored.block(0), Some(&genesis()), "genesis is in RAM");
        assert!(
            restored.block(8).is_none(),
            "historical blocks are not in RAM after restore"
        );
        for height in 1..=8 {
            assert!(
                restored.block(height).is_none(),
                "height {height} must not be in RAM after restore"
            );
        }
        assert!(restored.block(10).is_none(), "beyond tip");
        assert_eq!(restored.tip_hash(), tip_hash);
        assert_eq!(restored.height(), 9);

        // Blocks pushed after restore keep being served: the window
        // extends from the restored tip onward.
        let mut extended = restored;
        let b10 = child(&extended, vec![update_domain_tx("example.uip", 1, 8)]);
        extended.push_block(&b10).unwrap();
        assert_eq!(extended.block(9), Some(&tip_block));
        assert_eq!(extended.block(10), Some(&b10));
        assert!(extended.block(8).is_none());
    }

    // ---- anti-replay window (ported from the .bak) ----

    /// Empty blocks advancing the height (testnet fixtures have no
    /// producer authorization — the permissive consensus accepts any
    /// header, and empty blocks always apply).
    fn advance(chain: &mut Blockchain, blocks: u64) {
        for _ in 0..blocks {
            chain.push_block(&child(chain, vec![])).unwrap();
        }
    }

    #[test]
    fn replay_window_rejects_reinclusion_then_prunes() {
        // Register d.uip at height 2; its TXID is protected for
        // REPLAY_WINDOW_BLOCKS blocks, then the index entry is pruned
        // deterministically (pure function of the inclusion height).
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let register = register_domain_tx("d.uip", 1);
        let txid = transaction_id(&register).unwrap();
        chain
            .push_block(&child(&chain, vec![register.clone()]))
            .unwrap();
        let tx_h = chain.height(); // 2
        assert!(chain.is_tx_included(&txid));

        // Same transaction re-included in a later block: rejected
        // whole while its TXID is in the window (boundary-1: tip =
        // tx_h + WINDOW - 1 still protects it).
        advance(&mut chain, REPLAY_WINDOW_BLOCKS - 1);
        assert_eq!(chain.height(), tx_h + REPLAY_WINDOW_BLOCKS - 1);
        assert!(chain.is_tx_included(&txid), "still inside the window");
        let replay_block = child(&chain, vec![register.clone()]);
        assert_eq!(
            chain.push_block(&replay_block),
            Err(BlockchainError::TxReplay)
        );

        // Boundary: pushing block tx_h + WINDOW prunes the entry
        // (retain(h > tx_h)), and a block re-including the very same
        // bytes is no longer a replay — it applies under the ordinary
        // domain rules (here: DomainAlreadyRegistered, NOT TxReplay).
        advance(&mut chain, 1);
        assert_eq!(chain.height(), tx_h + REPLAY_WINDOW_BLOCKS);
        assert!(
            !chain.is_tx_included(&txid),
            "TXID pruned at the window boundary"
        );
        let replay_block = child(&chain, vec![register]);
        assert_eq!(
            chain.push_block(&replay_block),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
    }

    #[test]
    fn replay_window_index_is_bounded() {
        // One tx per block over more than WINDOW blocks: the index
        // never exceeds the window size (bounded RAM, independent of
        // the chain lifetime).
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        let extra: u64 = REPLAY_WINDOW_BLOCKS + 8;
        for i in 0..extra {
            let tx = update_domain_tx("example.uip", 1, i + 1);
            chain.push_block(&child(&chain, vec![tx])).unwrap();
        }
        let _ = chain.height();
        // The exposed predicate is window-only; the bound is checked
        // indirectly: the very first update (height 2) is outside the
        // window (tip = 2 + extra - 1 > 2 + WINDOW) and no longer
        // reported as included.
        let first = update_domain_tx("example.uip", 1, 1);
        let id = transaction_id(&first).unwrap();
        assert!(!chain.is_tx_included(&id));
        // …while the LAST update is still protected.
        let last = update_domain_tx("example.uip", 1, extra);
        assert!(chain.is_tx_included(&transaction_id(&last).unwrap()));
    }

    #[test]
    fn duplicate_tx_inside_one_block_is_caught_by_state_rules() {
        // Two copies of the same RegisterDomain in one block: the
        // anti-replay index is filled AFTER a successful push, so the
        // first copy applies and the second is rejected by the
        // ordinary state rule (the .bak checks intra-block
        // duplicates with a seen-set at the same place).
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let tx = register_domain_tx("dup.uip", 1);
        let block = child(&chain, vec![tx.clone(), tx]);
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
    }

    #[test]
    fn restored_chain_rebuilds_replay_index_from_window_entries() {
        // M8: `restore` itself still does not replay blocks (the
        // index starts empty), but the storage layer now rebuilds it
        // at boot through the public `rebuild_replay_index` API —
        // the same entries, at their original inclusion heights.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let tx = register_domain_tx("example.uip", 1);
        let id = transaction_id(&tx).unwrap();
        chain.push_block(&child(&chain, vec![tx])).unwrap();
        assert!(chain.is_tx_included(&id));
        let mut restored = Blockchain::restore(
            chain.height(),
            chain.tip_hash(),
            chain.block(chain.height()).unwrap().clone(),
            chain.state().clone(),
        );
        assert!(
            !restored.is_tx_included(&id),
            "restore alone still starts empty"
        );
        restored.rebuild_replay_index(std::iter::once((id, 2)));
        assert!(restored.is_tx_included(&id));
        assert_eq!(restored.replay_index_len(), 1);
    }

    #[test]
    fn rebuild_replay_index_prunes_like_push_block() {
        // Same pure rule as push_block: an entry survives while its
        // inclusion height stays above tip - REPLAY_WINDOW_BLOCKS.
        // Feeding entries from outside the window is a no-op, so a
        // caller scanning the full history converges on the same
        // index as one scanning only the tail.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        let extra = REPLAY_WINDOW_BLOCKS + 8;
        for i in 0..extra {
            chain
                .push_block(&child(
                    &chain,
                    vec![update_domain_tx("example.uip", 1, i + 1)],
                ))
                .unwrap();
        }
        let tip = chain.height();
        let cutoff = tip - REPLAY_WINDOW_BLOCKS;

        let mut restored = Blockchain::restore(
            tip,
            chain.tip_hash(),
            chain.block(tip).unwrap().clone(),
            chain.state().clone(),
        );
        // Outside the window: ignored. At the boundary: kept.
        // Intra-window duplicates: one entry per distinct TxId.
        let old = transaction_id(&update_domain_tx("example.uip", 1, 1)).unwrap();
        let boundary = transaction_id(&update_domain_tx("example.uip", 1, extra - 1)).unwrap();
        let last = transaction_id(&update_domain_tx("example.uip", 1, extra)).unwrap();
        restored.rebuild_replay_index(
            [
                (old, cutoff),          // == cutoff: pruned
                (boundary, cutoff + 1), // first live height
                (last, tip),
                (last, tip), // duplicate: collapses
            ]
            .into_iter(),
        );
        assert!(!restored.is_tx_included(&old));
        assert!(restored.is_tx_included(&boundary));
        assert!(restored.is_tx_included(&last));
        assert_eq!(restored.replay_index_len(), 2);
        // An entry above the tip cannot exist canonically: ignored.
        restored.rebuild_replay_index(std::iter::once((old, tip + 1)));
        assert!(!restored.is_tx_included(&old));
    }

    #[test]
    fn rebuilt_index_rejects_replay_after_restore() {
        // The point of M8: a tx re-included within the window is
        // rejected on a restored chain too — TxReplay, exactly like
        // a live node, not the state-rule backstop.
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        let tx = update_domain_tx("example.uip", 1, 1);
        chain
            .push_block(&child(&chain, vec![register_domain_tx("example.uip", 1)]))
            .unwrap();
        let tx_h = chain.height() + 1;
        chain.push_block(&child(&chain, vec![tx.clone()])).unwrap();
        advance(&mut chain, REPLAY_WINDOW_BLOCKS - 1);

        let tip = chain.height();
        let mut restored = Blockchain::restore(
            tip,
            chain.tip_hash(),
            chain.block(tip).unwrap().clone(),
            chain.state().clone(),
        );
        restored.rebuild_replay_index(std::iter::once((transaction_id(&tx).unwrap(), tx_h)));
        // The original block bytes replayed at tip+1: TxReplay.
        let replay_block = child(&restored, vec![tx]);
        assert_eq!(
            restored.push_block(&replay_block),
            Err(BlockchainError::TxReplay)
        );
    }

    // ---- bounded RAM window (M7a) ----

    /// The four test owner keys: after claiming `uip` (seed 1) and
    /// registering one domain per key (seeds 2-4), the eligibility
    /// pool holds exactly these 4 keys — the full testnet committee
    /// (committee_size 4, top-4 of 4, quorum 3).
    fn committee_keys() -> Vec<SigningKey> {
        (1..=4u8).map(|i| SigningKey::from_bytes([i; 32])).collect()
    }

    /// Chain whose PoS pool holds 4 distinct live owners: finality is
    /// available (committee ≥ MIN_FINALITY_COMMITTEE_SIZE).
    fn chain_with_committee() -> Blockchain {
        let mut chain = Blockchain::new();
        claim_open_uip(&mut chain, 1);
        for (name, seed) in [("a.uip", 2u8), ("b.uip", 3), ("c.uip", 4)] {
            chain
                .push_block(&child(&chain, vec![register_domain_tx(name, seed)]))
                .unwrap();
        }
        chain
    }

    /// Finalizes a checkpoint on the current tip, signed by the full
    /// committee (all 4 pool keys).
    fn finalize_tip(chain: &mut Blockchain) {
        let data = chain.checkpoint_data(0).unwrap();
        let committee = chain.committee(0);
        assert!(
            committee.len() >= scone_core::MIN_FINALITY_COMMITTEE_SIZE,
            "test fixture must reach the BFT floor"
        );
        let keys = committee_keys();
        let sigs: Vec<_> = keys
            .iter()
            .map(|sk| (sk.public_key(), sk.sign(&data.signing_hash())))
            .collect();
        let cp = scone_core::checkpoint::Checkpoint {
            data,
            signatures: sigs,
        };
        chain.accept_checkpoint(cp).unwrap();
    }

    #[test]
    fn bootstrap_without_finality_never_evicts() {
        // Before the first finalized checkpoint, NOTHING leaves RAM
        // (a reorg anywhere must stay possible): bounded RAM starts
        // with finality. Pinned deliberately — this is the M7a rule,
        // not an oversight.
        let mut chain = chain_with_committee();
        advance(&mut chain, RAM_WINDOW_BLOCKS + 20);
        assert_eq!(chain.base_height, 0);
        assert_eq!(chain.canonical.len() as u64, chain.height() + 1);
        assert!(chain.finality_floor().is_none());
    }

    #[test]
    fn ram_window_bounds_block_footprint() {
        // > 512 blocks with finality advancing as the chain grows
        // (a checkpoint every 100 blocks, like a live network): the
        // RAM footprint stays bounded by the window — blocks AND the
        // hash index — while the chain keeps pushing and validating.
        let mut chain = chain_with_committee();
        let step = 100u64;
        while chain.height() < RAM_WINDOW_BLOCKS + 200 {
            advance(&mut chain, step);
            finalize_tip(&mut chain);
        }
        let tip = chain.height();
        assert!(tip > RAM_WINDOW_BLOCKS + 100);
        // Window: genesis + the last RAM_WINDOW_BLOCKS heights.
        assert_eq!(
            chain.canonical.len() as u64,
            RAM_WINDOW_BLOCKS + 1,
            "genesis + window of canonical blocks in RAM"
        );
        assert_eq!(chain.known_hashes.len(), RAM_WINDOW_BLOCKS as usize + 1);
        // The eviction is real: heights below the window are gone…
        let base = chain.base_height;
        assert_eq!(base, tip - RAM_WINDOW_BLOCKS + 1);
        assert!(chain.block(base - 1).is_none());
        assert_eq!(
            chain.block_result(base - 1),
            Err(BlockchainError::BlockPruned { height: base - 1 })
        );
        // …the window itself is served…
        assert!(chain.block(base).is_some());
        assert!(chain.block(tip).is_some());
        // …and genesis never leaves RAM.
        assert_eq!(chain.block(0), Some(&genesis()));

        // The chain still validates real transactions after the
        // window slid: a fresh registration applies and reaches the
        // state.
        chain
            .push_block(&child(&chain, vec![register_domain_tx("fresh.uip", 1)]))
            .unwrap();
        assert!(chain.state().domain(&domain_id("fresh.uip")).is_some());
    }

    #[test]
    fn finality_floor_locks_eviction_above_it() {
        // ONE early checkpoint (height 12), then a long chain: the
        // floor pins every block above it in RAM — eviction NEVER
        // crosses the finality floor, even far outside the window
        // (a reorg down to the floor must stay possible).
        let mut chain = chain_with_committee();
        let to_go = 12 - chain.height();
        advance(&mut chain, to_go);
        assert_eq!(chain.height(), 12);
        finalize_tip(&mut chain);
        let floor = chain.finality_floor().unwrap();
        assert_eq!(floor, 12);
        advance(&mut chain, RAM_WINDOW_BLOCKS + 100);
        let tip = chain.height();
        assert!(tip - floor > RAM_WINDOW_BLOCKS, "window far past the floor");
        assert_eq!(chain.base_height, floor, "eviction stops at the floor");
        // Blocks below the floor left RAM (typed pruned)…
        assert!(chain.block(floor - 1).is_none());
        assert_eq!(
            chain.block_result(floor - 1),
            Err(BlockchainError::BlockPruned { height: floor - 1 })
        );
        // …the floor block and everything above stayed — the
        // footprint exceeds the window by design, finality is the
        // only eviction authority above it.
        assert!(chain.block(floor).is_some());
        assert_eq!(
            chain.canonical.len() as u64,
            1 + (tip - floor) + 1,
            "genesis + floor..=tip retained"
        );
        // The pinned window is still internally consistent: every
        // retained height serves its block and its hash.
        for h in [floor, floor + 1, tip - 1, tip] {
            let b = chain.block(h).expect("retained height");
            assert_eq!(
                chain.block_hash_at(h),
                Some(crate::block_hash::block_hash(&b.header).unwrap())
            );
        }
    }

    #[test]
    fn pruned_parent_is_a_typed_error_on_every_path() {
        // With the window slid past height 50, a block building on
        // the evicted block at 50 is rejected with the TYPED
        // BlockPruned error — on the linear push path, on
        // try_attach, and on full branch adoption — telling the
        // relay to reload the segment from the node store (or fall
        // back to a full sync) instead of just dropping the block.
        let mut chain = chain_with_committee();
        let to_go = 60 - chain.height();
        advance(&mut chain, to_go);
        let hash50 = crate::block_hash::block_hash(&chain.block(50).unwrap().header).unwrap();
        finalize_tip(&mut chain); // floor 60
        advance(&mut chain, RAM_WINDOW_BLOCKS + 100);
        assert!(chain.base_height > 50, "height 50 evicted");

        let orphan = make_block(hash50, 51, vec![]);
        assert_eq!(
            chain.push_block(&orphan),
            Err(BlockchainError::BlockPruned { height: 50 })
        );
        assert_eq!(
            chain.try_attach(&orphan).map(|_| ()),
            Err(BlockchainError::BlockPruned { height: 50 })
        );
        // Full branch adoption: same typed error (the fork point
        // itself is below the window).
        let second = make_block(
            crate::block_hash::block_hash(&orphan.header).unwrap(),
            52,
            vec![],
        );
        assert_eq!(
            chain.adopt_branch(&[orphan, second]),
            Err(BlockchainError::BlockPruned { height: 50 })
        );
        // The chain itself is untouched by the attempts.
        assert!(chain.height() > RAM_WINDOW_BLOCKS + 100);
    }

    #[test]
    fn restored_chain_reports_pruned_below_base() {
        // The restored-chain window (M3) reports the same typed
        // error as the eviction path: historical heights are the
        // node store's job.
        let mut chain = chain_with_committee();
        advance(&mut chain, 10);
        let restored = Blockchain::restore(
            chain.height(),
            chain.tip_hash(),
            chain.block(chain.height()).unwrap().clone(),
            chain.state().clone(),
        );
        assert_eq!(
            restored.block_result(1),
            Err(BlockchainError::BlockPruned { height: 1 })
        );
        assert!(restored.block_result(restored.height()).is_ok());
    }
}
