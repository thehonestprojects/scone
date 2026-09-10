//! Block identity.

use scone_protocol::codec::encode_to_vec;
use scone_protocol::{BlockHash, BlockHeader};

use crate::error::Result;

/// Domain-separation prefix for [`block_hash`].
pub const BLOCK_HASH_VERSION: &[u8] = b"SCONE-BLOCK-V1";

/// Computes the deterministic hash of a block from its canonical
/// header:
///
/// ```text
/// BlockHash = BLAKE3-256("SCONE-BLOCK-V1" || canonical_encode(BlockHeader))
/// ```
///
/// The transactions are **not** hashed again here: the header's
/// `tx_root` already commits to the ordered transaction list
/// (see [`crate::merkle`]), giving the chain
///
/// ```text
/// transactions -> TxIds -> MerkleRoot -> BlockHeader -> BlockHash
/// ```
///
/// # Errors
///
/// Returns an error if the header cannot be canonically encoded (zero
/// or future version, oversized consensus payload). Never panics.
pub fn block_hash(header: &BlockHeader) -> Result<BlockHash> {
    let encoded = encode_to_vec(header)?;
    Ok(BlockHash::from_bytes(scone_crypto::hash256(&[
        BLOCK_HASH_VERSION,
        &encoded,
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_protocol::{MerkleRoot, PROTOCOL_VERSION};

    fn header() -> BlockHeader {
        BlockHeader {
            version: PROTOCOL_VERSION,
            height: 42,
            prev_hash: BlockHash::from_bytes([1; 32]),
            tx_root: MerkleRoot::from_bytes([2; 32]),
            timestamp: 1_700_000_000,
            consensus: vec![0xaa; 8],
        }
    }

    #[test]
    fn deterministic() {
        assert_eq!(
            block_hash(&header()).unwrap(),
            block_hash(&header()).unwrap()
        );
    }

    #[test]
    fn matches_documented_formula() {
        let encoded = encode_to_vec(&header()).unwrap();
        let expected = scone_crypto::hash256(&[BLOCK_HASH_VERSION, &encoded]);
        assert_eq!(*block_hash(&header()).unwrap().as_bytes(), expected);
    }

    #[test]
    fn header_field_sensitivity() {
        let base = block_hash(&header()).unwrap();

        let mut other = header();
        other.height += 1;
        assert_ne!(block_hash(&other).unwrap(), base);

        let mut other = header();
        other.prev_hash = BlockHash::from_bytes([3; 32]);
        assert_ne!(block_hash(&other).unwrap(), base);

        let mut other = header();
        other.tx_root = MerkleRoot::from_bytes([4; 32]);
        assert_ne!(block_hash(&other).unwrap(), base);

        let mut other = header();
        other.timestamp += 1;
        assert_ne!(block_hash(&other).unwrap(), base);

        let mut other = header();
        other.consensus = vec![0xbb; 8];
        assert_ne!(block_hash(&other).unwrap(), base);
    }

    #[test]
    fn tx_root_change_changes_block_hash() {
        // transactions -> MerkleRoot -> BlockHash: a modified
        // transaction (or their order) changes tx_root, hence the hash.
        let mut other = header();
        other.tx_root = MerkleRoot::from_bytes([5; 32]);
        assert_ne!(block_hash(&other).unwrap(), block_hash(&header()).unwrap());
    }

    #[test]
    fn invalid_version_is_an_error_not_a_panic() {
        for version in [0u32, PROTOCOL_VERSION + 1] {
            let mut other = header();
            other.version = version;
            assert!(block_hash(&other).is_err(), "version {version}");
        }
    }

    #[test]
    fn oversized_consensus_is_an_error() {
        let mut other = header();
        other.consensus = vec![0; 257];
        assert!(block_hash(&other).is_err());
    }
}
