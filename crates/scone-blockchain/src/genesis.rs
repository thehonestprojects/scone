//! Deterministic genesis block, one per network (M8b).

use scone_core::{NetworkId, NetworkParams, TESTNET};
use scone_protocol::{Block, BlockHash, BlockHeader, PROTOCOL_VERSION};

use crate::merkle::merkle_root;

/// Timestamp of the genesis block: zero by convention — the genesis
/// carries no wall-clock meaning, it is purely structural. This
/// constant is part of the protocol.
pub const GENESIS_TIMESTAMP: u64 = 0;

/// Returns the genesis block of `params.network_id`, identical for
/// every node of that network and different from the genesis of any
/// other network.
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
/// | `consensus` | the canonical network id bytes (M8b network separation) |
/// | transactions | empty |
///
/// The network id inside the `consensus` payload makes genesis hashes
/// — and therefore every block hash chain — disjoint between
/// `scone-testnet` and `scone-mainnet`: a block of one network can
/// never attach to the other (`UnknownParent`), and no replay is
/// possible without re-signing everything.
#[must_use]
pub fn genesis_of(params: &NetworkParams) -> Block {
    let mut consensus = Vec::with_capacity(params.network_id.as_bytes().len());
    consensus.extend_from_slice(params.network_id.as_bytes());
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: 0,
            prev_hash: BlockHash::from_bytes([0; 32]),
            tx_root: merkle_root(&[]),
            timestamp: GENESIS_TIMESTAMP,
            consensus,
        },
        transactions: Vec::new(),
    }
}

/// Hash of the genesis block of `network` (same on every node of that
/// network, distinct across networks).
///
/// Encoding the genesis header cannot fail (every field is a protocol
/// constant), so this never panics.
#[must_use]
pub fn genesis_hash_of(network: NetworkId) -> BlockHash {
    let params = if network == NetworkId::MAINNET {
        scone_core::MAINNET
    } else {
        TESTNET
    };
    crate::block_hash::block_hash(&genesis_of(&params).header)
        .expect("genesis header is valid by construction")
}

/// Backwards-compatible alias: the **testnet** genesis (the project's
/// development default since M8b).
#[must_use]
pub fn genesis() -> Block {
    genesis_of(&TESTNET)
}

/// Backwards-compatible alias: the **testnet** genesis hash.
#[must_use]
pub fn genesis_hash() -> BlockHash {
    genesis_hash_of(TESTNET.network_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{EMPTY_ROOT_LABEL, MERKLE_VERSION};
    use scone_core::{MAINNET, NetworkId};

    #[test]
    fn deterministic_across_calls() {
        assert_eq!(genesis(), genesis());
        assert_eq!(genesis_hash(), genesis_hash());
        assert_eq!(
            genesis_of(&MAINNET),
            genesis_of(&scone_core::NetworkParams {
                network_id: NetworkId::MAINNET,
                tld_pow_difficulty: MAINNET.tld_pow_difficulty,
                domain_pow_difficulty: MAINNET.domain_pow_difficulty,
            })
        );
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
        assert_eq!(genesis.header.consensus, b"scone-testnet".to_vec());
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn genesis_hash_matches_block_hash_formula() {
        assert_eq!(
            genesis_hash(),
            crate::block_hash::block_hash(&genesis().header).unwrap()
        );
    }

    #[test]
    fn networks_have_disjoint_genesis() {
        // M8b acceptance: the two networks' genesis blocks differ (by
        // the consensus payload) and so do their hashes — no block
        // can ever cross over.
        let t = genesis_of(&TESTNET);
        let m = genesis_of(&MAINNET);
        assert_ne!(t, m);
        assert_ne!(
            genesis_hash_of(TESTNET.network_id),
            genesis_hash_of(NetworkId::MAINNET)
        );
        assert_eq!(t.header.consensus, b"scone-testnet".to_vec());
        assert_eq!(m.header.consensus, b"scone-mainnet".to_vec());
    }
}
