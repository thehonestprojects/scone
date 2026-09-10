//! Deterministic genesis block.

use scone_protocol::{Block, BlockHash, BlockHeader, PROTOCOL_VERSION};

use crate::merkle::merkle_root;

/// Timestamp of the genesis block: zero by convention — the genesis
/// carries no wall-clock meaning, it is purely structural. This
/// constant is part of the protocol.
pub const GENESIS_TIMESTAMP: u64 = 0;

/// Returns the genesis block, identical for every node.
///
/// Reproducible from protocol constants alone (no randomness, no local
/// clock, no network):
///
/// | Field | Value |
/// |---|---|
/// | `version` | [`PROTOCOL_VERSION`] |
/// | `height` | `0` |
/// | `prev_hash` | 32 zero bytes (there is no previous block) |
/// | `tx_root` | Merkle root of an empty transaction list |
/// | `timestamp` | [`GENESIS_TIMESTAMP`] (`0`) |
/// | `consensus` | empty |
/// | transactions | empty |
#[must_use]
pub fn genesis() -> Block {
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: 0,
            prev_hash: BlockHash::from_bytes([0; 32]),
            tx_root: merkle_root(&[]),
            timestamp: GENESIS_TIMESTAMP,
            consensus: Vec::new(),
        },
        transactions: Vec::new(),
    }
}

/// Hash of the genesis block (same on every node).
///
/// Encoding the genesis header cannot fail (every field is a protocol
/// constant), so this never panics.
#[must_use]
pub fn genesis_hash() -> BlockHash {
    crate::block_hash::block_hash(&genesis().header)
        .expect("genesis header is valid by construction")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{EMPTY_ROOT_LABEL, MERKLE_VERSION};

    #[test]
    fn deterministic_across_calls() {
        assert_eq!(genesis(), genesis());
        assert_eq!(genesis_hash(), genesis_hash());
    }

    #[test]
    fn documented_constants() {
        let genesis = genesis();
        assert_eq!(genesis.header.version, PROTOCOL_VERSION);
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.prev_hash, BlockHash::from_bytes([0; 32]));
        assert_eq!(
            *genesis.header.tx_root.as_bytes(),
            scone_crypto::hash256(&[MERKLE_VERSION, EMPTY_ROOT_LABEL])
        );
        assert_eq!(genesis.header.timestamp, GENESIS_TIMESTAMP);
        assert_eq!(genesis.header.consensus, Vec::<u8>::new());
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn genesis_hash_matches_block_hash_formula() {
        assert_eq!(
            genesis_hash(),
            crate::block_hash::block_hash(&genesis().header).unwrap()
        );
    }
}
