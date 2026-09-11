//! Checkpoint wire format (checkpoint finality over P2P).
//!
//! Ported from the `.bak` (M-wire): this module defines the CANONICAL
//! binary encoding of [`CheckpointData`] and [`Checkpoint`] for the
//! network (and the rebroadcast window). It is intentionally NOT the
//! signature preimage — signing uses
//! [`CheckpointData::signing_bytes`](scone_core::checkpoint::CheckpointData::signing_bytes)
//! (`SCONE-CKPT-V1 || epoch || height || recovery || block_hash ||
//! prev_checkpoint_hash || state_root`, little-endian, 116 B fixed) —
//! so the wire format can evolve without breaking signatures.
//!
//! ## `CheckpointData` (116 bytes, fixed, no tag)
//!
//! ```text
//! epoch(8 LE) || height(8 LE) || recovery(4 LE)
//!     || block_hash[32] || prev_checkpoint_hash[32] || state_root[32]
//! ```
//!
//! Little-endian fixed-width integers (like the signing preimage),
//! NOT varints: a checkpoint is a fixed-size commitment, and keeping
//! the body byte-identical to the preimage tail makes offline
//! cross-checks trivial.
//!
//! ## `Checkpoint` (`.bak` port)
//!
//! ```text
//! tag "SCONE-CKPT-V1" (13 B) || data (116 B)
//!     || count.v (varint) || pk[32] || sig[64]  … sorted by pk
//! ```
//!
//! Canonical form: signatures sorted strictly increasing by public
//! key, no duplicate signer. Decoding enforces sort order, dedup and
//! [`MAX_CHECKPOINT_SIGNERS`]; every malformed input is a typed
//! [`ProtocolError`], never a panic (see `message.rs` fuzz tests).

use scone_core::checkpoint::{Checkpoint, CheckpointData};
use scone_crypto::{PublicKey, Signature};

use crate::codec::{Decode, Encode};
use crate::error::{ProtocolError, Result};
use crate::varint;

/// Wire tag of an encoded checkpoint (domain separation of the
/// format itself).
pub const CHECKPOINT_WIRE_TAG: &[u8] = b"SCONE-CKPT-V1";

/// Fixed length of the encoded `CheckpointData` body.
pub const CHECKPOINT_DATA_LEN: usize = 8 + 8 + 4 + 32 + 32 + 32;

/// Maximum signatures carried by one checkpoint on the wire
/// (production committee = 31 anchors + 4 recovery draws = 35; 64
/// leaves headroom while staying a hard bound before allocation).
pub const MAX_CHECKPOINT_SIGNERS: usize = 64;

const _: () = assert!(CHECKPOINT_DATA_LEN == 116);

impl Encode for CheckpointData {
    /// Appends the fixed 116-byte body (no tag — the tag belongs to
    /// the [`Checkpoint`] envelope).
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.recovery.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.prev_checkpoint_hash);
        out.extend_from_slice(&self.state_root);
        Ok(())
    }
}

impl Decode for CheckpointData {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let body = take_fixed::<CHECKPOINT_DATA_LEN>(input)?;
        Ok(CheckpointData {
            epoch: u64::from_le_bytes(body[0..8].try_into().expect("fixed body")),
            height: u64::from_le_bytes(body[8..16].try_into().expect("fixed body")),
            recovery: u32::from_le_bytes(body[16..20].try_into().expect("fixed body")),
            block_hash: body[20..52].try_into().expect("fixed body"),
            prev_checkpoint_hash: body[52..84].try_into().expect("fixed body"),
            state_root: body[84..116].try_into().expect("fixed body"),
        })
    }
}

impl Encode for Checkpoint {
    /// Appends the tagged envelope: `tag || data || count.v || pairs`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::LimitExceeded`] if the signature count exceeds
    /// [`MAX_CHECKPOINT_SIGNERS`]; [`ProtocolError::NonCanonical`] if
    /// the signature list is not sorted strictly increasing by public
    /// key (canonical form is enforced at encode time too, so two
    /// honest nodes always produce identical bytes).
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(CHECKPOINT_WIRE_TAG);
        self.data.encode(out)?;
        if self.signatures.len() > MAX_CHECKPOINT_SIGNERS {
            return Err(ProtocolError::LimitExceeded("checkpoint signers"));
        }
        varint::put_u64(self.signatures.len() as u64, out);
        let mut prev: Option<[u8; 32]> = None;
        for (pk, sig) in &self.signatures {
            let bytes = pk.to_bytes();
            if let Some(p) = prev
                && bytes <= p
            {
                return Err(ProtocolError::NonCanonical(
                    "checkpoint signatures must be sorted by pk, no duplicates",
                ));
            }
            prev = Some(bytes);
            out.extend_from_slice(&bytes);
            out.extend_from_slice(&sig.to_bytes());
        }
        Ok(())
    }
}

impl Decode for Checkpoint {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let tag = take_fixed::<{ CHECKPOINT_WIRE_TAG.len() }>(input)?;
        if tag != CHECKPOINT_WIRE_TAG {
            return Err(ProtocolError::NonCanonical("bad checkpoint tag"));
        }
        let data = CheckpointData::decode(input)?;
        let count = varint::take_u64(input)?;
        if count > MAX_CHECKPOINT_SIGNERS as u64 {
            return Err(ProtocolError::LimitExceeded("checkpoint signers"));
        }
        let count = count as usize;
        // Bound checked BEFORE allocation: a lying count can never
        // force an absurd allocation.
        if input.len() < count * 96 {
            return Err(ProtocolError::Truncated);
        }
        let mut signatures = Vec::with_capacity(count);
        let mut prev: Option<[u8; 32]> = None;
        for _ in 0..count {
            let pk_bytes: [u8; 32] = take_fixed(input)?;
            let sig_bytes: [u8; 64] = take_fixed(input)?;
            if let Some(p) = prev
                && pk_bytes <= p
            {
                return Err(ProtocolError::NonCanonical(
                    "checkpoint signatures must be sorted by pk, no duplicates",
                ));
            }
            prev = Some(pk_bytes);
            let pk = PublicKey::from_bytes(pk_bytes)
                .map_err(|_| ProtocolError::InvalidTransactionKey)?;
            signatures.push((pk, Signature::from_bytes(sig_bytes)));
        }
        Ok(Checkpoint { data, signatures })
    }
}

/// Reads a fixed-size array without prefix (`pub(crate)` sibling of
/// `codec::take_array`, which is private to that module).
fn take_fixed<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
    if input.len() < N {
        return Err(ProtocolError::Truncated);
    }
    let (head, rest) = input.split_at(N);
    let mut array = [0u8; N];
    array.copy_from_slice(head);
    *input = rest;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_complete, encode_to_vec};
    use scone_crypto::SigningKey;

    fn keys(n: u8) -> Vec<SigningKey> {
        (1..=n).map(|i| SigningKey::from_bytes([i; 32])).collect()
    }

    fn data(epoch: u64, height: u64, salt: u8) -> CheckpointData {
        CheckpointData {
            epoch,
            height,
            block_hash: [salt; 32],
            prev_checkpoint_hash: [salt.wrapping_add(1); 32],
            state_root: [salt.wrapping_add(2); 32],
            recovery: 0,
        }
    }

    fn signed(data: &CheckpointData, keys: &[SigningKey]) -> Checkpoint {
        let msg = data.signing_hash();
        let mut signatures: Vec<(PublicKey, Signature)> = keys
            .iter()
            .map(|sk| (sk.public_key(), sk.sign(&msg)))
            .collect();
        signatures.sort_by_key(|s| s.0);
        Checkpoint {
            data: data.clone(),
            signatures,
        }
    }

    #[test]
    fn data_roundtrip_and_length() {
        let d = data(7, 777, 9);
        let bytes = encode_to_vec(&d).unwrap();
        assert_eq!(bytes.len(), CHECKPOINT_DATA_LEN);
        assert_eq!(decode_complete::<CheckpointData>(&bytes).unwrap(), d);
    }

    #[test]
    fn data_encoding_is_deterministic() {
        let d = data(1, 2, 3);
        assert_eq!(encode_to_vec(&d).unwrap(), encode_to_vec(&d).unwrap());
    }

    #[test]
    fn checkpoint_roundtrip_empty_and_signed() {
        let d = data(2, 20, 5);
        let empty = Checkpoint {
            data: d.clone(),
            signatures: Vec::new(),
        };
        assert_eq!(
            decode_complete::<Checkpoint>(&encode_to_vec(&empty).unwrap()).unwrap(),
            empty
        );
        let ks = keys(4);
        let cp = signed(&d, &ks);
        let bytes = encode_to_vec(&cp).unwrap();
        // tag + body + varint + 4 * 96
        assert_eq!(
            bytes.len(),
            CHECKPOINT_WIRE_TAG.len() + CHECKPOINT_DATA_LEN + 1 + 4 * 96
        );
        assert_eq!(decode_complete::<Checkpoint>(&bytes).unwrap(), cp);
    }

    #[test]
    fn quorum_survives_the_wire() {
        let ks = keys(4);
        let cp = signed(&data(1, 10, 1), &ks);
        let decoded = decode_complete::<Checkpoint>(&encode_to_vec(&cp).unwrap()).unwrap();
        let committee: Vec<PublicKey> = ks.iter().map(|k| k.public_key()).collect();
        assert!(decoded.verify_quorum(&committee, 3));
    }

    #[test]
    fn wire_body_matches_signing_preimage_tail() {
        // The 116-byte body must equal signing_bytes() minus the tag:
        // offline cross-check of a signature against wire bytes is
        // then a pure prefix split.
        let d = data(3, 300, 7);
        let body = encode_to_vec(&d).unwrap();
        let preimage = d.signing_bytes();
        assert_eq!(&preimage[CHECKPOINT_WIRE_TAG.len()..], &body[..]);
    }

    #[test]
    fn truncated_never_decodes_nor_panics() {
        let cp = signed(&data(1, 10, 1), &keys(3));
        let bytes = encode_to_vec(&cp).unwrap();
        for end in 0..bytes.len() {
            assert!(
                decode_complete::<Checkpoint>(&bytes[..end]).is_err(),
                "prefix {end} must not decode"
            );
        }
        // A bare CheckpointData body is total over 116 bytes: only
        // strictly shorter prefixes fail.
        let body = encode_to_vec(&data(1, 10, 1)).unwrap();
        for end in 0..body.len() {
            assert_eq!(
                decode_complete::<CheckpointData>(&body[..end]).is_err(),
                end < CHECKPOINT_DATA_LEN,
                "prefix {end} of the data body"
            );
        }
    }

    #[test]
    fn corrupted_never_panics() {
        let cp = signed(&data(1, 10, 1), &keys(3));
        let bytes = encode_to_vec(&cp).unwrap();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut c = bytes.clone();
                c[i] ^= mask;
                let _ = decode_complete::<Checkpoint>(&c);
                let _ = decode_complete::<CheckpointData>(&c);
            }
        }
    }

    #[test]
    fn bad_tag_rejected() {
        let cp = signed(&data(1, 10, 1), &keys(2));
        let mut bytes = encode_to_vec(&cp).unwrap();
        bytes[0] ^= 0x01;
        assert!(matches!(
            decode_complete::<Checkpoint>(&bytes),
            Err(ProtocolError::NonCanonical(_))
        ));
        // Completely foreign buffer: rejected (either truncated before
        // the tag, or non-canonical tag) — never decoded, never a panic.
        assert!(decode_complete::<Checkpoint>(&[0xff; 8]).is_err());
        assert!(decode_complete::<Checkpoint>(&[0xff; 64]).is_err());
    }

    #[test]
    fn signer_bound_enforced_before_allocation() {
        // Announce 65 signers but provide no payload: limit, not
        // truncation, and no huge allocation.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CHECKPOINT_WIRE_TAG);
        data(0, 1, 0).encode(&mut bytes).unwrap();
        varint::put_u64(MAX_CHECKPOINT_SIGNERS as u64 + 1, &mut bytes);
        assert!(matches!(
            decode_complete::<Checkpoint>(&bytes),
            Err(ProtocolError::LimitExceeded("checkpoint signers"))
        ));
        // Exactly at the bound with a truncated payload: Truncated.
        let mut at = bytes.clone();
        at.truncate(at.len() - 1);
        varint::put_u64(MAX_CHECKPOINT_SIGNERS as u64, &mut at);
        assert!(matches!(
            decode_complete::<Checkpoint>(&at),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn unsorted_and_duplicate_signers_rejected() {
        let d = data(1, 10, 1);
        let ks = keys(3);
        let mut cp = signed(&d, &ks);
        // Duplicate a signature.
        cp.signatures.push(cp.signatures[0]);
        assert!(matches!(
            encode_to_vec(&cp),
            Err(ProtocolError::NonCanonical(_))
        ));
        // Hand-build an unsorted wire form.
        let mut cp2 = signed(&d, &ks);
        cp2.signatures.reverse();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CHECKPOINT_WIRE_TAG);
        cp2.data.encode(&mut bytes).unwrap();
        varint::put_u64(cp2.signatures.len() as u64, &mut bytes);
        for (pk, sig) in &cp2.signatures {
            bytes.extend_from_slice(&pk.to_bytes());
            bytes.extend_from_slice(&sig.to_bytes());
        }
        assert!(matches!(
            decode_complete::<Checkpoint>(&bytes),
            Err(ProtocolError::NonCanonical(_))
        ));
    }

    #[test]
    fn max_signers_roundtrip() {
        let ks = keys(8);
        let mut pool: Vec<SigningKey> = ks.clone();
        // Grow past the production committee size (35) up to the cap.
        for i in 8..64u8 {
            pool.push(SigningKey::from_bytes([i | 0x80; 32]));
        }
        let d = data(1, 10, 2);
        let cp = signed(&d, &pool);
        assert_eq!(cp.signatures.len(), MAX_CHECKPOINT_SIGNERS);
        assert_eq!(
            decode_complete::<Checkpoint>(&encode_to_vec(&cp).unwrap()).unwrap(),
            cp
        );
        // One more signer: refused at encode.
        let mut over = cp.clone();
        over.signatures.push((
            SigningKey::from_bytes([9; 32]).public_key(),
            cp.signatures[0].1,
        ));
        over.signatures.sort_by_key(|s| s.0);
        assert!(matches!(
            encode_to_vec(&over),
            Err(ProtocolError::LimitExceeded("checkpoint signers"))
        ));
    }

    #[test]
    fn empty_data_roundtrip() {
        let d = CheckpointData {
            epoch: 0,
            height: 0,
            block_hash: [0; 32],
            prev_checkpoint_hash: [0; 32],
            state_root: [0; 32],
            recovery: 0,
        };
        assert_eq!(
            decode_complete::<CheckpointData>(&encode_to_vec(&d).unwrap()).unwrap(),
            d
        );
    }

    #[test]
    fn max_u64_fields_roundtrip() {
        let d = CheckpointData {
            epoch: u64::MAX,
            height: u64::MAX,
            block_hash: [1; 32],
            prev_checkpoint_hash: [2; 32],
            state_root: [3; 32],
            recovery: u32::MAX,
        };
        assert_eq!(
            decode_complete::<CheckpointData>(&encode_to_vec(&d).unwrap()).unwrap(),
            d
        );
    }
}
