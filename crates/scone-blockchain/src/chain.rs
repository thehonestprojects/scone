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
/// Fork handling (minimum, see `/docs/blockchain.md`): a block whose
/// parent was never seen is rejected with
/// [`BlockchainError::UnknownParent`]; a block building on a known
/// non-tip block is rejected with [`BlockchainError::ParentNotTip`]. No
/// received block is ever treated as canonical before passing full
/// validation. Real fork choice belongs to the future consensus.
#[derive(Debug)]
pub struct Blockchain<C: Consensus = PermissiveConsensus> {
    /// Canonical blocks; index == height, `canonical[0]` is genesis.
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

impl<C: Consensus> Blockchain<C> {
    /// New chain at genesis with a custom consensus.
    #[must_use]
    pub fn with_consensus(consensus: C) -> Self {
        let hash = genesis_hash();
        Self {
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

    /// Canonical block at `height`, if it exists.
    #[must_use]
    pub fn block(&self, height: u64) -> Option<&Block> {
        usize::try_from(height)
            .ok()
            .and_then(|i| self.canonical.get(i))
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
        // Version: same rule as the wire format (non-zero, not future).
        if header.version == 0 || header.version > PROTOCOL_VERSION {
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

        // Transactions: consensus validation and deterministic
        // application, on a scratch state (atomic per block).
        // ponytail: full state clone per block; revert-journal if the domain count makes it costly
        let mut next_state = self.state.clone();
        for tx in &block.transactions {
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
    use scone_core::{
        DomainId, DomainName, OwnerId, Proof, RecordHash, Register, Transaction, Update,
    };
    use scone_protocol::codec::{decode_complete, encode_to_vec};
    use scone_protocol::{BlockHeader, MerkleRoot};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    fn register_tx(name: &str, owner_byte: u8) -> Transaction {
        Transaction::Register(Register {
            domain_id: domain_id(name),
            owner: OwnerId::from_bytes([owner_byte; 32]),
            timestamp: 1,
            proof: Proof::from_bytes(Vec::new()),
        })
    }

    fn update_tx(name: &str, owner_byte: u8, sequence: u64) -> Transaction {
        Transaction::Update(Update {
            domain_id: domain_id(name),
            owner: OwnerId::from_bytes([owner_byte; 32]),
            sequence,
            record_hash: RecordHash::from_bytes([sequence as u8; 32]),
            timestamp: 1,
        })
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
        assert_eq!(domain.owner, OwnerId::from_bytes([1; 32]));
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
}
