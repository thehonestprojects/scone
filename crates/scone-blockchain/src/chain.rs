//! Canonical in-memory chain and block validation.

use std::collections::HashSet;

use scone_protocol::limits::MAX_TXS_PER_BLOCK;
use scone_protocol::{Block, BlockHash, PROTOCOL_VERSION};

use crate::block_hash::block_hash;
use crate::consensus::{Consensus, PermissiveConsensus};
use crate::error::{BlockchainError, Result};
use crate::genesis::{genesis, genesis_hash};
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
    /// live chain (`canonical` is dense: index == height, genesis at
    /// index 0). On a chain restored via [`Blockchain::restore`] only
    /// genesis and the tip window are in RAM: historical heights in
    /// `1..base_height` are served from the node store and
    /// [`block`](Self::block) returns `None` for them.
    base_height: u64,
    /// Canonical blocks held in RAM: dense from genesis on a live
    /// chain (`canonical[0]` is genesis, index == height), or
    /// `[genesis, restored tip, blocks pushed since]` on a restored
    /// chain (see `base_height`).
    canonical: Vec<Block>,
    /// Hashes of every accepted block (parent classification for fork
    /// detection).
    known_hashes: HashSet<BlockHash>,
    tip: BlockHash,
    state: ChainState,
    consensus: C,
}

impl Blockchain<PermissiveConsensus> {
    /// New chain at genesis with the permissive placeholder consensus.
    #[must_use]
    pub fn new() -> Self {
        Self::with_consensus(PermissiveConsensus)
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
        let genesis_h = genesis_hash();
        Self {
            base_height: tip_height,
            canonical: vec![genesis(), tip_block],
            known_hashes: HashSet::from([genesis_h, tip]),
            tip,
            state,
            consensus: PermissiveConsensus,
        }
    }
}

impl<C: Consensus> Blockchain<C> {
    /// New chain at genesis with a custom consensus.
    #[must_use]
    pub fn with_consensus(consensus: C) -> Self {
        let hash = genesis_hash();
        Self {
            base_height: 0,
            canonical: vec![genesis()],
            known_hashes: HashSet::from([hash]),
            tip: hash,
            state: ChainState::new(),
            consensus,
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
    /// Blocks of the current session are in RAM; on a chain restored
    /// from storage (see [`Blockchain::restore`]) only genesis, the
    /// restored tip and blocks pushed since are — historical blocks
    /// are served from the node store, and this returns [`None`]
    /// for them.
    #[must_use]
    pub fn block(&self, height: u64) -> Option<&Block> {
        if height == 0 {
            // Genesis is always in RAM (`canonical[0]` on a live
            // chain, prepended by `restore`).
            return self.canonical.first().filter(|g| g.header.height == 0);
        }
        // Heights below `base_height` (a restored chain's historical
        // window) are not in RAM. On a restored chain the genesis
        // slot prepended by `restore` shifts the window by one; a
        // live chain (`base_height == 0`) is dense (index == height).
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

    /// Authoritative state after all applied blocks.
    #[must_use]
    pub fn state(&self) -> &ChainState {
        &self.state
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
        let header = &block.header;

        // Parent: must extend the canonical tip.
        if header.prev_hash != self.tip {
            return Err(if self.known_hashes.contains(&header.prev_hash) {
                BlockchainError::ParentNotTip
            } else {
                BlockchainError::UnknownParent
            });
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

        let hash = block_hash(header)?;

        // Consensus hooks (PoW etc. — future).
        self.consensus.validate_header(header)?;

        // Transactions: cryptographic validation (owner/key binding
        // recomputed, signature over the recomputed canonical
        // payload), consensus hooks and deterministic application, on
        // a scratch state (atomic per block).
        // ponytail: full state clone per block; revert-journal if the domain count makes it costly
        let mut next_state = self.state.clone();
        for tx in &block.transactions {
            validate_transaction(tx)?;
            self.consensus.validate_tx(tx)?;
            next_state.apply(tx)?;
        }

        self.known_hashes.insert(hash);
        self.canonical.push(block.clone());
        self.tip = hash;
        self.state = next_state;
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BlockchainError;
    use crate::txid::transaction_id;
    use scone_core::{DomainId, DomainName, Proof, RecordHash, Register, Transaction, Update};
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
            Transaction::Register(mut r) => {
                r.signature = sk.sign(&payload);
                Transaction::Register(r)
            }
            Transaction::Update(mut u) => {
                u.signature = sk.sign(&payload);
                Transaction::Update(u)
            }
        }
    }

    fn unsigned_register(name: &str, seed: u8) -> Transaction {
        Transaction::Register(Register::register_signed(
            domain_id(name),
            1,
            Proof::from_bytes(Vec::new()),
            SigningKey::from_bytes([seed; 32]).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn register_tx(name: &str, seed: u8) -> Transaction {
        sign(
            unsigned_register(name, seed),
            &SigningKey::from_bytes([seed; 32]),
        )
    }

    fn unsigned_update(name: &str, seed: u8, sequence: u64) -> Transaction {
        Transaction::Update(Update::update_signed(
            domain_id(name),
            sequence,
            RecordHash::from_bytes([sequence as u8; 32]),
            SigningKey::from_bytes([seed; 32]).public_key(),
            Signature::from_bytes([0; 64]),
        ))
    }

    fn update_tx(name: &str, seed: u8, sequence: u64) -> Transaction {
        sign(
            unsigned_update(name, seed, sequence),
            &SigningKey::from_bytes([seed; 32]),
        )
    }

    fn make_block(prev: BlockHash, height: u64, txs: Vec<Transaction>) -> Block {
        Block {
            header: BlockHeader {
                version: PROTOCOL_VERSION,
                height,
                prev_hash: prev,
                tx_root: tx_root(&txs).unwrap(),
                timestamp: height, // deterministic placeholder
                consensus: Vec::new(),
            },
            transactions: txs,
        }
    }

    fn child<C: crate::Consensus>(chain: &Blockchain<C>, txs: Vec<Transaction>) -> Block {
        make_block(chain.tip_hash(), chain.height() + 1, txs)
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
        let b1 = child(&chain, vec![register_tx("example.uip", 1)]);
        let h1 = chain.push_block(&b1).unwrap();
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.tip_hash(), h1);
        assert_eq!(chain.tip(), &b1);

        let b2 = child(&chain, vec![update_tx("example.uip", 1, 1)]);
        let h2 = chain.push_block(&b2).unwrap();
        assert_eq!(chain.height(), 2);
        assert_eq!(chain.tip_hash(), h2);
        assert_eq!(chain.block(1), Some(&b1));
        assert_eq!(chain.block(2), Some(&b2));
    }

    #[test]
    fn register_then_update_reaches_the_state() {
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(&chain, vec![register_tx("example.uip", 1)]))
            .unwrap();
        chain
            .push_block(&child(&chain, vec![update_tx("example.uip", 1, 1)]))
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
        chain
            .push_block(&child(
                &chain,
                vec![
                    register_tx("example.uip", 1),
                    update_tx("example.uip", 1, 1),
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

        let b1 = child(
            &left,
            vec![register_tx("a.uip", 1), register_tx("b.uip", 2)],
        );
        left.push_block(&b1).unwrap();
        right.push_block(&b1).unwrap();

        let b2 = child(&left, vec![update_tx("a.uip", 1, 1)]);
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
        chain
            .push_block(&child(&chain, vec![register_tx("a.uip", 1)]))
            .unwrap();

        // Competing block on the same (now non-tip) genesis parent.
        let competitor = make_block(genesis_hash, 1, vec![register_tx("b.uip", 1)]);
        assert_eq!(
            chain.push_block(&competitor),
            Err(BlockchainError::ParentNotTip)
        );
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.state().domain(&domain_id("b.uip")), None);
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
        // 0, future versions AND the old v1 format are all rejected.
        for version in [0u32, 1, PROTOCOL_VERSION + 1] {
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
            .map(|i| register_tx(&format!("d{i}.uip"), 1))
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
        let mut block = child(&chain, vec![register_tx("example.uip", 1)]);
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
        let txs = vec![register_tx("a.uip", 1), register_tx("b.uip", 1)];
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
        // Update on an unregistered domain.
        let block = child(&chain, vec![update_tx("example.uip", 1, 1)]);
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
        let snapshot_state = chain.state().clone();
        let tip = chain.tip_hash();

        let block = child(
            &chain,
            vec![
                register_tx("a.uip", 1),
                register_tx("b.uip", 2),
                register_tx("a.uip", 3), // double register: fails
            ],
        );
        assert_eq!(
            chain.push_block(&block),
            Err(BlockchainError::DomainAlreadyRegistered)
        );
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.tip_hash(), tip);
        assert_eq!(*chain.state(), snapshot_state);
    }

    #[test]
    fn transaction_order_is_significant() {
        // [register, update] applies; [update, register] does not.
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(
                &chain,
                vec![
                    register_tx("example.uip", 1),
                    update_tx("example.uip", 1, 1),
                ],
            ))
            .unwrap();

        let mut chain2 = Blockchain::new();
        let block = child(
            &chain2,
            vec![
                update_tx("example.uip", 1, 1),
                register_tx("example.uip", 1),
            ],
        );
        assert_eq!(
            chain2.push_block(&block),
            Err(BlockchainError::UnknownDomain)
        );
    }

    #[test]
    fn reversed_transactions_different_block_hash() {
        let mut chain = Blockchain::new();
        let ab = child(
            &chain,
            vec![register_tx("a.uip", 1), register_tx("b.uip", 1)],
        );
        let ba = child(
            &chain,
            vec![register_tx("b.uip", 1), register_tx("a.uip", 1)],
        );
        let hash_ab = chain.push_block(&ab.clone()).unwrap();
        let hash_ba = {
            let mut other = Blockchain::new();
            other.push_block(&ba).unwrap();
            other.tip_hash()
        };
        assert_ne!(hash_ab, hash_ba);
    }

    #[test]
    fn long_update_chain() {
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(&chain, vec![register_tx("example.uip", 1)]))
            .unwrap();
        for sequence in 1..=50 {
            chain
                .push_block(&child(&chain, vec![update_tx("example.uip", 1, sequence)]))
                .unwrap();
        }
        let domain = chain.state().domain(&domain_id("example.uip")).unwrap();
        assert_eq!(domain.sequence, 50);
        assert_eq!(chain.height(), 51);
    }

    #[test]
    fn update_from_previous_block_owner_rules_hold() {
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(&chain, vec![register_tx("example.uip", 1)]))
            .unwrap();
        // Wrong owner, correct sequence.
        let block = child(&chain, vec![update_tx("example.uip", 2, 1)]);
        assert_eq!(chain.push_block(&block), Err(BlockchainError::NotOwner));
        // Wrong owner and wrong sequence: owner is checked first.
        let block = child(&chain, vec![update_tx("example.uip", 2, 5)]);
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
            if matches!(tx, Transaction::Register(r) if r.domain_id == domain_id("pow.uip")) {
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
            vec![register_tx("pow.uip", 1), register_tx("other.uip", 1)],
        );
        assert!(matches!(
            chain.push_block(&block),
            Err(BlockchainError::Consensus(msg)) if msg == "pow missing"
        ));
        // The chain still accepts blocks without a `pow.uip` register.
        chain
            .push_block(&child(&chain, vec![register_tx("other.uip", 1)]))
            .unwrap();
    }

    #[test]
    fn chain_unchanged_after_every_rejection_kind() {
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(&chain, vec![register_tx("example.uip", 1)]))
            .unwrap();
        let (height, tip, state) = (chain.height(), chain.tip_hash(), chain.state().clone());

        let cases: Vec<Block> = vec![
            make_block(BlockHash::from_bytes([9; 32]), 1, vec![]), // unknown parent
            make_block(chain.tip_hash(), 7, vec![]),               // bad height
            make_block(chain.tip_hash(), 2, vec![update_tx("no.uip", 1, 1)]), // bad tx
        ];
        for block in cases {
            assert!(chain.push_block(&block).is_err());
            assert_eq!(chain.height(), height);
            assert_eq!(chain.tip_hash(), tip);
            assert_eq!(*chain.state(), state);
        }

        let mut bad_root = child(&chain, vec![register_tx("z.uip", 1)]);
        bad_root.header.tx_root = MerkleRoot::from_bytes([1; 32]);
        assert!(chain.push_block(&bad_root).is_err());
        assert_eq!(chain.height(), height);
    }

    #[test]
    fn corrupted_encoded_blocks_never_panic() {
        let mut chain = Blockchain::new();
        let block = child(&chain, vec![register_tx("example.uip", 1)]);
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
    fn txids_are_stable_across_nodes() {
        // The TxId of a transaction inside a block does not depend on
        // the node computing it (no local clock, no position).
        let tx = register_tx("example.uip", 1);
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
        let mut tx = register_tx("example.uip", 1);
        if let Transaction::Register(r) = &mut tx {
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
        let mut tx = unsigned_register("example.uip", 2);
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
        let mut tx = register_tx("example.uip", 1);
        if let Transaction::Register(r) = &mut tx {
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
        let tx = unsigned_register("example.uip", 2);
        // Consistent signature by seed 2's key…
        let tx = sign(tx, &SigningKey::from_bytes([2; 32]));
        // …but a forged owner field. The forgery is built at the WIRE
        // level (encode valid → flip the owner bytes → decode): the
        // in-memory API cannot construct an owner-forged Register
        // anymore (Encode validates the binding, docs/transactions.md).
        let mut raw = scone_protocol::encode_to_vec(&tx).unwrap();
        // Layout: disc(1) version(1) domain_id(32) owner(32) ...
        raw[2 + 32..2 + 64].copy_from_slice(
            crate::validate::owner_from_public_key(&SigningKey::from_bytes([9; 32]).public_key())
                .as_bytes(),
        );
        let forged_result = scone_protocol::decode_complete::<Transaction>(&raw);
        assert!(
            forged_result.is_err(),
            "owner-forged Register must be rejected on decode (binding owner/pk)"
        );
        // Defense in depth: the chain itself also refuses a forged owner
        // if one ever reaches push (e.g. built in memory then validated).
        // (Covered by `signature_by_non_matching_key_is_rejected` path.)
    }

    #[test]
    fn forged_update_for_someone_elses_domain_is_rejected() {
        // The attacker (seed 2) correctly signs an Update but the
        // domain belongs to seed 1: NotOwner at application time.
        let mut chain = Blockchain::new();
        chain
            .push_block(&child(&chain, vec![register_tx("example.uip", 1)]))
            .unwrap();
        let attack = update_tx("example.uip", 2, 1);
        let block = child(&chain, vec![attack]);
        assert_eq!(chain.push_block(&block), Err(BlockchainError::NotOwner));
    }

    #[test]
    fn signed_chain_genesis_block1_block2_deterministic_replay() {
        let assemble = || {
            let sk = SigningKey::from_bytes([5; 32]);
            let mut chain = Blockchain::new();
            chain
                .push_block(&child(&chain, vec![register_tx("example.uip", 5)]))
                .unwrap();
            let _ = sk;
            chain
                .push_block(&child(&chain, vec![update_tx("example.uip", 5, 1)]))
                .unwrap();
            chain
                .push_block(&child(&chain, vec![update_tx("example.uip", 5, 2)]))
                .unwrap();
            chain
        };
        let left = assemble();
        let right = assemble();
        assert_eq!(left.height(), 3);
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
        chain
            .push_block(&child(&chain, vec![register_tx("example.uip", 1)]))
            .unwrap();
        for height in 2..=8 {
            chain
                .push_block(&child(
                    &chain,
                    vec![update_tx("example.uip", 1, height - 1)],
                ))
                .unwrap();
        }
        assert_eq!(chain.height(), 8);
        let tip_hash = chain.tip_hash();
        let tip_block = chain.block(8).unwrap().clone();

        let restored = Blockchain::restore(8, tip_hash, tip_block.clone(), chain.state().clone());

        assert_eq!(restored.block(8), Some(&tip_block), "tip is in RAM");
        assert_eq!(restored.block(0), Some(&genesis()), "genesis is in RAM");
        assert!(
            restored.block(7).is_none(),
            "historical blocks are not in RAM after restore"
        );
        for height in 1..=7 {
            assert!(
                restored.block(height).is_none(),
                "height {height} must not be in RAM after restore"
            );
        }
        assert!(restored.block(9).is_none(), "beyond tip");
        assert_eq!(restored.tip_hash(), tip_hash);
        assert_eq!(restored.height(), 8);

        // Blocks pushed after restore keep being served: the window
        // extends from the restored tip onward.
        let mut extended = restored;
        let b9 = child(&extended, vec![update_tx("example.uip", 1, 8)]);
        extended.push_block(&b9).unwrap();
        assert_eq!(extended.block(8), Some(&tip_block));
        assert_eq!(extended.block(9), Some(&b9));
        assert!(extended.block(7).is_none());
    }
}
