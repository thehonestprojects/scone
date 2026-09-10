//! Merkle tree over transaction ids.
//!
//! Spec (see `/docs/blockchain.md`):
//!
//! ```text
//! 0 tx     root = BLAKE3-256("SCONE-MERKLE-V1" || "EMPTY")
//! leaf     BLAKE3-256("SCONE-MERKLE-V1" || 0x00 || TxId)
//! node     BLAKE3-256("SCONE-MERKLE-V1" || 0x01 || left || right)
//! odd level  the last hash is duplicated to complete the pair
//! ```
//!
//! The transaction order is **significant** and is never sorted: two
//! blocks with the same transactions in a different order produce
//! different roots.

use scone_core::Transaction;
use scone_protocol::MerkleRoot;

use crate::error::Result;
use crate::txid::{TxId, transaction_id};

/// Domain-separation prefix for every hash of this module (distinct
/// from `SCONE-TX-V1` and `SCONE-BLOCK-V1`).
pub const MERKLE_VERSION: &[u8] = b"SCONE-MERKLE-V1";

/// Label hashed to build the root of an empty transaction list.
pub const EMPTY_ROOT_LABEL: &[u8] = b"EMPTY";

/// Leaf tag (second-preimage protection: a leaf can never be confused
/// with an internal node).
const LEAF_TAG: u8 = 0x00;
/// Internal node tag.
const NODE_TAG: u8 = 0x01;

fn leaf_hash(txid: &TxId) -> [u8; 32] {
    scone_crypto::hash256(&[MERKLE_VERSION, &[LEAF_TAG], txid.as_bytes()])
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    scone_crypto::hash256(&[MERKLE_VERSION, &[NODE_TAG], left, right])
}

/// Computes the Merkle root over `txids`, **in the given order**.
///
/// Never panics; allocations are bounded by the input length (a block
/// is itself bounded by `MAX_TXS_PER_BLOCK`).
#[must_use]
pub fn merkle_root(txids: &[TxId]) -> MerkleRoot {
    if txids.is_empty() {
        return MerkleRoot::from_bytes(scone_crypto::hash256(&[MERKLE_VERSION, EMPTY_ROOT_LABEL]));
    }
    let mut level: Vec<[u8; 32]> = txids.iter().map(leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = level.get(i + 1).copied().unwrap_or(left);
            next.push(node_hash(&left, &right));
            i += 2;
        }
        level = next;
    }
    MerkleRoot::from_bytes(level[0])
}

/// Computes the commitment of a block's transaction list: `TxId`s are
/// computed first, then hashed into the tree, in block order.
///
/// # Errors
///
/// Returns an error if any transaction cannot be canonically encoded.
/// Never panics.
pub fn tx_root(transactions: &[Transaction]) -> Result<MerkleRoot> {
    let txids: Result<Vec<TxId>> = transactions.iter().map(transaction_id).collect();
    Ok(merkle_root(&txids?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::txid::TX_ID_VERSION;
    use scone_core::{DomainId, DomainName, OwnerId, Proof, RecordHash, Register, Update};

    fn txid(byte: u8) -> TxId {
        TxId::from_bytes([byte; 32])
    }

    fn register_tx(name: &str) -> scone_core::Transaction {
        scone_core::Transaction::Register(Register {
            domain_id: DomainId::from_name(&DomainName::new(name).unwrap()),
            owner: OwnerId::from_bytes([1; 32]),
            timestamp: 1,
            proof: Proof::from_bytes(Vec::new()),
        })
    }

    fn update_tx(name: &str, sequence: u64) -> scone_core::Transaction {
        scone_core::Transaction::Update(Update {
            domain_id: DomainId::from_name(&DomainName::new(name).unwrap()),
            owner: OwnerId::from_bytes([1; 32]),
            sequence,
            record_hash: RecordHash::from_bytes([sequence as u8; 32]),
            timestamp: 1,
        })
    }

    #[test]
    fn empty_root_matches_documented_formula() {
        let expected = scone_crypto::hash256(&[MERKLE_VERSION, EMPTY_ROOT_LABEL]);
        assert_eq!(*merkle_root(&[]).as_bytes(), expected);
        assert_ne!(
            merkle_root(&[]),
            MerkleRoot::from_bytes(scone_crypto::hash256(&[MERKLE_VERSION]))
        );
    }

    #[test]
    fn single_tx_root_is_the_leaf_hash() {
        assert_eq!(
            merkle_root(&[txid(0x01)]),
            MerkleRoot::from_bytes(leaf_hash(&txid(0x01)))
        );
    }

    #[test]
    fn two_txs_root_is_the_node_hash() {
        let expected = node_hash(&leaf_hash(&txid(1)), &leaf_hash(&txid(2)));
        assert_eq!(
            merkle_root(&[txid(1), txid(2)]),
            MerkleRoot::from_bytes(expected)
        );
    }

    #[test]
    fn three_txs_duplicate_last() {
        let l1 = leaf_hash(&txid(1));
        let l2 = leaf_hash(&txid(2));
        let l3 = leaf_hash(&txid(3));
        let expected = node_hash(&node_hash(&l1, &l2), &node_hash(&l3, &l3));
        assert_eq!(
            merkle_root(&[txid(1), txid(2), txid(3)]),
            MerkleRoot::from_bytes(expected)
        );
    }

    #[test]
    fn four_txs_manual_computation() {
        let l1 = leaf_hash(&txid(1));
        let l2 = leaf_hash(&txid(2));
        let l3 = leaf_hash(&txid(3));
        let l4 = leaf_hash(&txid(4));
        let expected = node_hash(&node_hash(&l1, &l2), &node_hash(&l3, &l4));
        assert_eq!(
            merkle_root(&[txid(1), txid(2), txid(3), txid(4)]),
            MerkleRoot::from_bytes(expected)
        );
    }

    #[test]
    fn odd_sizes_are_deterministic() {
        for count in [1usize, 3, 5, 7, 9, 15] {
            let ids: Vec<TxId> = (1..=count as u8).map(txid).collect();
            assert_eq!(merkle_root(&ids), merkle_root(&ids), "{count} txs");
        }
    }

    #[test]
    fn order_changes_the_root() {
        let cases: [&[TxId]; 4] = [
            &[txid(1), txid(2)],
            &[txid(1), txid(2), txid(3)],
            &[txid(1), txid(2), txid(3), txid(4)],
            &[txid(1), txid(2), txid(3), txid(4), txid(5)],
        ];
        for ids in cases {
            let mut swapped = ids.to_vec();
            swapped.swap(0, 1);
            assert_ne!(merkle_root(ids), merkle_root(&swapped));
        }
    }

    #[test]
    fn leaf_and_node_tags_prevent_second_preimage() {
        // A leaf hash and a node hash are never equal, and no TxId can
        // be mistaken for an internal node input.
        let leaf = leaf_hash(&txid(1));
        let node = node_hash(txid(1).as_bytes(), txid(2).as_bytes());
        assert_ne!(leaf, node);
        assert_ne!(
            leaf_hash(&txid(1)),
            node_hash(&leaf_hash(&txid(1)), &leaf_hash(&txid(1)))
        );
    }

    #[test]
    fn tx_root_over_transactions_matches_txids_root() {
        let txs = [register_tx("example.uip"), update_tx("example.uip", 1)];
        let ids: Vec<TxId> = txs
            .iter()
            .map(transaction_id)
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(tx_root(&txs).unwrap(), merkle_root(&ids));
    }

    #[test]
    fn tx_root_empty_matches_merkle_empty() {
        assert_eq!(tx_root(&[]).unwrap(), merkle_root(&[]));
    }

    #[test]
    fn tx_root_order_matters() {
        let ab = tx_root(&[register_tx("a.uip"), register_tx("b.uip")]).unwrap();
        let ba = tx_root(&[register_tx("b.uip"), register_tx("a.uip")]).unwrap();
        assert_ne!(ab, ba);
    }

    #[test]
    fn tx_root_invalid_transaction_is_an_error() {
        // sequence = 0 violates a core invariant: encoding must fail,
        // not panic.
        assert!(tx_root(&[update_tx("example.uip", 0)]).is_err());
    }

    #[test]
    fn domain_separator_is_distinct_from_txid() {
        // A TxId and a leaf over the same-looking bytes must never
        // collide: distinct domain prefixes guarantee it.
        let encoded = b"payload".as_slice();
        let tx_like = scone_crypto::hash256(&[TX_ID_VERSION, encoded]);
        let leaf_like = scone_crypto::hash256(&[MERKLE_VERSION, &[LEAF_TAG], &tx_like]);
        assert_ne!(tx_like, leaf_like);
    }
}
