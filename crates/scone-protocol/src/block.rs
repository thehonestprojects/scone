//! Block container format.
//!
//! Defines the *protocol container* only. Consensus rules (proof-of-work
//! fields, difficulty, chain selection) belong to the future
//! `scone-blockchain` crate; the header keeps an opaque, bounded
//! [`BlockHeader::consensus`] payload for them. `BlockHash` and
//! `tx_root` computations (over the canonical header / transaction
//! encodings defined here) are also blockchain-layer concerns.

use scone_core::Transaction;

use crate::PROTOCOL_VERSION;
use crate::codec::{self, Decode, Encode};
use crate::error::{ProtocolError, Result};
use crate::limits;
use crate::varint;

/// Hash of a block: commitment over the canonical block-header encoding,
/// computed by the future blockchain crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes (decoded from storage or the wire).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for BlockHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Encode for BlockHash {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_array(self.as_bytes(), out);
        Ok(())
    }
}

impl Decode for BlockHash {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(codec::take_array(input)?))
    }
}

/// Merkle root over a block's transaction list, computed by the future
/// blockchain crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes (decoded from storage or the wire).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for MerkleRoot {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Encode for MerkleRoot {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_array(self.as_bytes(), out);
        Ok(())
    }
}

impl Decode for MerkleRoot {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(codec::take_array(input)?))
    }
}

/// Block header.
///
/// ```text
/// BlockHeader = version.v || height.v || prev_hash[32] || tx_root[32]
///             || timestamp.v || consensus(bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockHeader {
    /// Protocol version this block is encoded with
    /// (1..=[`PROTOCOL_VERSION`]).
    pub version: u32,
    /// Height of this block in the chain (genesis = 0).
    pub height: u64,
    /// Hash of the previous block; all zeros for genesis.
    pub prev_hash: BlockHash,
    /// Commitment over the transaction list (Merkle root; the tree is
    /// defined by the future blockchain crate).
    pub tx_root: MerkleRoot,
    /// Ordering information (Unix timestamp, seconds).
    pub timestamp: u64,
    /// Opaque consensus payload (proof-of-work fields, etc.), defined by
    /// the future consensus rules; bounded by
    /// [`limits::MAX_CONSENSUS_LEN`].
    pub consensus: Vec<u8>,
}

fn check_version(version: u32) -> Result<()> {
    if version == 0 || version > PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(u64::from(version)));
    }
    // Format v1 (pre-signature transactions, milestone M1) is a
    // different, incompatible block format: rejected explicitly
    // rather than mis-parsed.
    if version < PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(u64::from(version)));
    }
    Ok(())
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        check_version(self.version)?;
        self.version.encode(out)?;
        varint::put_u64(self.height, out);
        codec::put_array(self.prev_hash.as_bytes(), out);
        codec::put_array(self.tx_root.as_bytes(), out);
        varint::put_u64(self.timestamp, out);
        codec::put_bounded(
            &self.consensus,
            limits::MAX_CONSENSUS_LEN,
            "consensus length",
            out,
        )
    }
}

impl Decode for BlockHeader {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let version = u32::decode(input)?;
        check_version(version)?;
        Ok(Self {
            version,
            height: u64::decode(input)?,
            prev_hash: BlockHash::from_bytes(codec::take_array(input)?),
            tx_root: MerkleRoot::from_bytes(codec::take_array(input)?),
            timestamp: u64::decode(input)?,
            consensus: codec::take_bytes(input, limits::MAX_CONSENSUS_LEN, "consensus length")?
                .to_vec(),
        })
    }
}

/// A block: header plus its ordered transaction list.
///
/// ```text
/// Block = BlockHeader || tx_count.v (<= MAX_TXS_PER_BLOCK) || transactions…
/// ```
///
/// Unlike DNS record sets, the transaction **order is significant**
/// (consensus ordering) and is preserved exactly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.transactions.len() > limits::MAX_TXS_PER_BLOCK {
            return Err(ProtocolError::LimitExceeded("transaction count"));
        }
        self.header.encode(out)?;
        varint::put_u64(self.transactions.len() as u64, out);
        for tx in &self.transactions {
            tx.encode(out)?;
        }
        Ok(())
    }
}

impl Decode for Block {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let header = BlockHeader::decode(input)?;
        let count = varint::take_u64(input)?;
        if count > limits::MAX_TXS_PER_BLOCK as u64 {
            return Err(ProtocolError::LimitExceeded("transaction count"));
        }
        let mut transactions = Vec::with_capacity(count as usize);
        for _ in 0..count {
            transactions.push(Transaction::decode(input)?);
        }
        Ok(Self {
            header,
            transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_complete, encode_to_vec};
    use scone_core::{DomainName, Proof, RecordHash, RegisterDomain, UpdateDomain};
    use scone_crypto::SigningKey;

    fn signer() -> SigningKey {
        SigningKey::from_bytes([1u8; 32])
    }

    fn register_domain_tx() -> Transaction {
        let sk = signer();
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new("example.uip").unwrap(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(b"fixture"),
        ))
    }

    fn update_domain_tx() -> Transaction {
        let sk = signer();
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            scone_core::DomainId::from_name(&DomainName::new("example.uip").unwrap()),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            sk.sign(b"fixture"),
        ))
    }

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

    fn block() -> Block {
        Block {
            header: header(),
            transactions: vec![register_domain_tx(), update_domain_tx()],
        }
    }

    #[test]
    fn header_roundtrip() {
        assert_eq!(
            decode_complete::<BlockHeader>(&encode_to_vec(&header()).unwrap()).unwrap(),
            header()
        );
    }

    #[test]
    fn block_roundtrip_preserves_tx_order() {
        let block = block();
        let decoded = decode_complete::<Block>(&encode_to_vec(&block).unwrap()).unwrap();
        assert_eq!(decoded, block);
        assert_eq!(decoded.transactions[0], register_domain_tx());
        assert_eq!(decoded.transactions[1], update_domain_tx());
    }

    #[test]
    fn encoding_is_deterministic() {
        assert_eq!(
            encode_to_vec(&block()).unwrap(),
            encode_to_vec(&block()).unwrap()
        );
    }

    #[test]
    fn zero_version_rejected() {
        let mut header = header();
        header.version = 0;
        assert!(matches!(
            encode_to_vec(&header),
            Err(ProtocolError::UnsupportedVersion(0))
        ));
        // Crafted on the wire: [0x00] is a valid minimal varint.
        assert!(matches!(
            decode_complete::<BlockHeader>(&[0x00]),
            Err(ProtocolError::UnsupportedVersion(0))
        ));
    }

    #[test]
    fn future_version_rejected() {
        let mut header = header();
        header.version = PROTOCOL_VERSION + 1;
        assert!(encode_to_vec(&header).is_err());
        assert!(matches!(
            decode_complete::<BlockHeader>(&[0x02]),
            Err(ProtocolError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn below_current_version_rejected() {
        // There is exactly one block format: version 1. A version
        // below it (only 0) is a version error, never mis-parsed.
        let mut header = header();
        header.version = 0;
        assert!(matches!(
            encode_to_vec(&header),
            Err(ProtocolError::UnsupportedVersion(0))
        ));
    }

    #[test]
    fn genesis_values_roundtrip() {
        let mut header = header();
        header.height = 0;
        header.timestamp = 0;
        header.prev_hash = BlockHash::from_bytes([0; 32]);
        assert_eq!(
            decode_complete::<BlockHeader>(&encode_to_vec(&header).unwrap()).unwrap(),
            header
        );
    }

    #[test]
    fn u64_max_height_roundtrips() {
        let mut header = header();
        header.height = u64::MAX;
        assert_eq!(
            decode_complete::<BlockHeader>(&encode_to_vec(&header).unwrap()).unwrap(),
            header
        );
    }

    #[test]
    fn consensus_boundaries() {
        let mut header = header();
        header.consensus = vec![0; limits::MAX_CONSENSUS_LEN];
        assert!(encode_to_vec(&header).is_ok());

        header.consensus = vec![0; limits::MAX_CONSENSUS_LEN + 1];
        assert!(matches!(
            encode_to_vec(&header),
            Err(ProtocolError::LimitExceeded("consensus length"))
        ));

        // Crafted wire form: header with empty consensus ends with a 0x00
        // length byte; replace it with an over-limit length.
        header.consensus = Vec::new();
        let bytes = encode_to_vec(&header).unwrap();
        let mut crafted = bytes[..bytes.len() - 1].to_vec();
        varint::put_u64(limits::MAX_CONSENSUS_LEN as u64 + 1, &mut crafted);
        assert!(matches!(
            decode_complete::<BlockHeader>(&crafted),
            Err(ProtocolError::LimitExceeded("consensus length"))
        ));
    }

    #[test]
    fn empty_block_roundtrips() {
        let block = Block {
            header: header(),
            transactions: Vec::new(),
        };
        assert_eq!(
            decode_complete::<Block>(&encode_to_vec(&block).unwrap()).unwrap(),
            block
        );
    }

    #[test]
    fn tx_count_limit_enforced() {
        // Encode side.
        let mut block = block();
        block.transactions = vec![register_domain_tx(); limits::MAX_TXS_PER_BLOCK + 1];
        assert!(matches!(
            encode_to_vec(&block),
            Err(ProtocolError::LimitExceeded("transaction count"))
        ));

        // Decode side: announced count alone triggers the limit before
        // any allocation.
        let mut bytes = encode_to_vec(&header()).unwrap();
        varint::put_u64(limits::MAX_TXS_PER_BLOCK as u64 + 1, &mut bytes);
        assert!(matches!(
            decode_complete::<Block>(&bytes),
            Err(ProtocolError::LimitExceeded("transaction count"))
        ));
    }

    #[test]
    fn truncated_block_rejected() {
        let bytes = encode_to_vec(&block()).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_complete::<Block>(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn corrupted_block_never_panics() {
        let bytes = encode_to_vec(&block()).unwrap();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut corrupted = bytes.clone();
                corrupted[i] ^= mask;
                let _ = decode_complete::<Block>(&corrupted);
            }
        }
    }
}
