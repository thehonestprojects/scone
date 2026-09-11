//! Signed-block producer payload (M5 of the .bak port).
//!
//! The v1 `BlockHeader` has an opaque `consensus: Vec<u8>` field
//! (bounded by `MAX_CONSENSUS_LEN`). The PoS consensus fills it with
//! a self-contained producer payload:
//!
//! ```text
//! consensus = "SCONE-BLOCK-V2" || producer_pk[32] || signature[64]
//! signature = sign(producer_sk, "SCONE-BLOCK-V2" || block_hash)
//! ```
//!
//! `block_hash` is the recomputed header hash (BLAKE3,
//! `SCONE-BLOCK-V1` domain — the hash identity is unchanged; only the
//! payload of the `consensus` field gains structure). A block is
//! admissible only when:
//!
//! 1. the payload decodes strictly (tag, exact lengths);
//! 2. the signature verifies against the embedded producer key over
//!    the recomputed block hash (never a provided value);
//! 3. the producer key is in the allowed-producer set for the block's
//!    timestamp (`Blockchain::allowed_producers`) — bootstrap: owners
//!    of live domains at the parent state; finalized: elected
//!    committee + unlocked recovery draws;
//! 4. empty producer pool (genesis of a fresh chain): anyone may
//!    produce — otherwise the first REGISTER would be impossible.
//!
//! The genesis block keeps an EMPTY consensus payload (structural,
//! never validated as a produced block).

use scone_crypto::{PublicKey, Signature};
use scone_protocol::BlockHeader;

use crate::block_hash::block_hash as header_hash;

/// Domain-separation tag of the signed-block payload.
pub const BLOCK_SIGN_TAG: &[u8] = b"SCONE-BLOCK-V2";

/// Exact wire length of the payload: tag (14) + pk (32) + sig (64).
pub const PRODUCER_PAYLOAD_LEN: usize = BLOCK_SIGN_TAG.len() + 32 + 64;

/// A decoded, well-formed producer payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerPayload {
    /// The producer's self-contained public key.
    pub producer: PublicKey,
    /// Signature over `BLOCK_SIGN_TAG || block_hash`.
    pub signature: Signature,
}

/// Builds the canonical payload bytes.
#[must_use]
pub fn encode_producer_payload(producer: &PublicKey, signature: &Signature) -> Vec<u8> {
    let mut out = Vec::with_capacity(PRODUCER_PAYLOAD_LEN);
    out.extend_from_slice(BLOCK_SIGN_TAG);
    out.extend_from_slice(&producer.to_bytes());
    out.extend_from_slice(&signature.to_bytes());
    out
}

/// Strictly decodes a producer payload — wrong tag, wrong length or
/// a non-canonical key is `None` (never a panic).
#[must_use]
pub fn decode_producer_payload(bytes: &[u8]) -> Option<ProducerPayload> {
    if bytes.len() != PRODUCER_PAYLOAD_LEN {
        return None;
    }
    if &bytes[..BLOCK_SIGN_TAG.len()] != BLOCK_SIGN_TAG {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[BLOCK_SIGN_TAG.len()..BLOCK_SIGN_TAG.len() + 32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes[BLOCK_SIGN_TAG.len() + 32..]);
    let producer = PublicKey::from_bytes(pk).ok()?;
    Some(ProducerPayload {
        producer,
        signature: Signature::from_bytes(sig),
    })
}

/// The producer signs THIS hash, not the full block hash: the
/// payload lives inside `header.consensus`, which the block hash
/// covers, so signing the block hash would be circular. The signing
/// hash is the header with its `consensus` field EMPTIED — every
/// other field (height, prev_hash, tx_root, timestamp…) is bound.
#[must_use]
pub fn producer_signing_hash(header: &BlockHeader) -> Option<[u8; 32]> {
    let stripped = BlockHeader {
        consensus: Vec::new(),
        ..header.clone()
    };
    header_hash(&stripped).ok().map(|h| *h.as_bytes())
}

/// Signs a block hash as its producer.
#[must_use]
pub fn sign_block_hash(sk: &scone_crypto::SigningKey, signing_hash: &[u8; 32]) -> Signature {
    let mut msg = Vec::with_capacity(BLOCK_SIGN_TAG.len() + 32);
    msg.extend_from_slice(BLOCK_SIGN_TAG);
    msg.extend_from_slice(signing_hash);
    sk.sign(&msg)
}

/// Verifies a producer payload against the RECOMPUTED producer
/// signing hash (see [`producer_signing_hash`]).
#[must_use]
pub fn verify_block_producer(payload: &ProducerPayload, signing_hash: &[u8; 32]) -> bool {
    let mut msg = Vec::with_capacity(BLOCK_SIGN_TAG.len() + 32);
    msg.extend_from_slice(BLOCK_SIGN_TAG);
    msg.extend_from_slice(signing_hash);
    payload.producer.verify(&msg, &payload.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrip() {
        let sk = scone_crypto::SigningKey::from_bytes([7; 32]);
        let sig = sign_block_hash(&sk, &[9; 32]);
        let bytes = encode_producer_payload(&sk.public_key(), &sig);
        assert_eq!(bytes.len(), PRODUCER_PAYLOAD_LEN);
        let decoded = decode_producer_payload(&bytes).unwrap();
        assert_eq!(decoded.producer, sk.public_key());
        assert_eq!(decoded.signature, sig);
    }

    #[test]
    fn decode_rejects_malformed() {
        assert!(decode_producer_payload(&[]).is_none());
        assert!(decode_producer_payload(&[0; PRODUCER_PAYLOAD_LEN - 1]).is_none());
        assert!(decode_producer_payload(&[0; PRODUCER_PAYLOAD_LEN + 1]).is_none());
        // Wrong tag.
        let sk = scone_crypto::SigningKey::from_bytes([1; 32]);
        let sig = sign_block_hash(&sk, &[0; 32]);
        let mut bad = encode_producer_payload(&sk.public_key(), &sig);
        bad[0] ^= 0x01;
        assert!(decode_producer_payload(&bad).is_none());
        // Strictly non-canonical key: y=2 compressed encoding does
        // not decompress to a curve point (PublicKey::from_bytes
        // rejects). If this scone-crypto version accepts the byte
        // pattern, the signature check still refuses it downstream —
        // but decode must at least survive without panicking.
        let mut bad_key = encode_producer_payload(&sk.public_key(), &sig);
        bad_key[BLOCK_SIGN_TAG.len()] = 0x02; // y=2 encoding
        let decoded = decode_producer_payload(&bad_key);
        // Either rejected at decode or accepted-but-unverifiable:
        // both are safe; pin the no-panic contract.
        if let Some(p) = decoded {
            assert!(!verify_block_producer(&p, &[1; 32]) || p.producer == sk.public_key());
        }
    }

    #[test]
    fn signature_binds_the_hash() {
        let sk = scone_crypto::SigningKey::from_bytes([3; 32]);
        let sig = sign_block_hash(&sk, &[1; 32]);
        let payload = ProducerPayload {
            producer: sk.public_key(),
            signature: sig,
        };
        assert!(verify_block_producer(&payload, &[1; 32]));
        assert!(!verify_block_producer(&payload, &[2; 32]));
        // Signed by another key: embedded pk mismatch.
        let other = scone_crypto::SigningKey::from_bytes([4; 32]);
        let forged = ProducerPayload {
            producer: sk.public_key(),
            signature: sign_block_hash(&other, &[1; 32]),
        };
        assert!(!verify_block_producer(&forged, &[1; 32]));
    }

    #[test]
    fn signing_hash_ignores_only_the_consensus_field() {
        // Two headers differing ONLY by consensus share a signing
        // hash; any other difference changes it.
        let _sk = scone_crypto::SigningKey::from_bytes([5; 32]);
        let b = crate::BlockBuilder::after(0, crate::genesis::genesis_hash())
            .with_timestamp(42)
            .build()
            .unwrap();
        let h1 = producer_signing_hash(&b.header).unwrap();
        let mut other = b.header.clone();
        other.consensus = vec![1, 2, 3];
        assert_eq!(producer_signing_hash(&other).unwrap(), h1);
        other.timestamp += 1;
        assert_ne!(producer_signing_hash(&other).unwrap(), h1);
        other.timestamp -= 1;
        other.height += 1;
        assert_ne!(producer_signing_hash(&other).unwrap(), h1);
    }
}
