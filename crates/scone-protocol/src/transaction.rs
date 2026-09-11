//! Wire encoding of blockchain transactions (format v2 — signed).
//!
//! ```text
//! Transaction = disc u8 || version u8 (0x02) || payload
//!   0x01 Register
//!   0x02 Update
//! ```
//!
//! The `version` byte after the discriminator is new in format v2: a
//! v1 stream (no version byte) is detected and rejected explicitly
//! with [`ProtocolError::UnsupportedVersion(1)`]. Old-format bytes are
//! never parsed as v2 by accident: after `0x01`/`0x02`, the old format
//! continued with the first byte of `domain_id`, whereas v2 requires
//! exactly `0x02`.
//!
//! Every transaction embeds the signer's Ed25519 public key (32 raw
//! bytes) and signature (exactly 64 raw bytes — no length prefix, no
//! headroom: any other size is a hard decode error).
//!
//! The signed payload is [`signing_payload`]: the `SCONE-TX-SIG-V1`
//! prefix followed by the canonical encoding of the transaction
//! **without** the signature. See `/docs/technical/transactions.md` (normative).

use scone_core::{DomainId, OwnerId, Proof, RecordHash, Register, Transaction, Update};
use scone_crypto::{PublicKey, Signature};

use crate::codec::{self, Decode, Encode};
use crate::error::{ProtocolError, Result};
use crate::varint;

/// Transaction wire discriminants.
pub mod tx_type {
    /// Claims ownership of a domain.
    pub const REGISTER: u8 = 0x01;
    /// Publishes a new version of a domain's DNS data.
    pub const UPDATE: u8 = 0x02;
}

/// Version byte of the signed transaction format (v2).
pub const TX_FORMAT_VERSION: u8 = 0x02;

/// Domain-separation prefix of the transaction signing payload.
pub const TX_SIG_PREFIX: &[u8] = b"SCONE-TX-SIG-V1";

// Proof = bytes (bounded, opaque; the registration proof of work is not
// defined yet)

impl Encode for Proof {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_bounded(
            self.as_bytes(),
            crate::limits::MAX_PROOF_LEN,
            "proof length",
            out,
        )
    }
}

impl Decode for Proof {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(
            codec::take_bytes(input, crate::limits::MAX_PROOF_LEN, "proof length")?.to_vec(),
        ))
    }
}

// PublicKey = 32 raw bytes (exactly; a non-decompressable encoding is
// rejected here already, weak keys are rejected at verify time).

impl Encode for PublicKey {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_array(&self.to_bytes(), out);
        Ok(())
    }
}

impl Decode for PublicKey {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let bytes = codec::take_array::<32>(input)?;
        Self::from_bytes(bytes).map_err(|_| ProtocolError::InvalidTransactionKey)
    }
}

// Signature = exactly 64 raw bytes, no prefix.

impl Encode for Signature {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_array(&self.to_bytes(), out);
        Ok(())
    }
}

impl Decode for Signature {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(codec::take_array::<64>(input)?))
    }
}

// Register = domain_id[32] || owner[32] || timestamp.v || proof
//          || public_key[32] || signature[64]

impl Encode for Register {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        // Binding owner/pk vérifié aussi à l'encodage (symétrie avec Update,
        // docs/transactions.md § Dérivation de l'owner — doc normative).
        self.validate()?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.timestamp, out);
        self.proof.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for Register {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let register = Self {
            domain_id: DomainId::decode(input)?,
            owner: OwnerId::decode(input)?,
            timestamp: u64::decode(input)?,
            proof: Proof::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        register.validate().map_err(ProtocolError::Validation)?;
        Ok(register)
    }
}

// Update = domain_id[32] || owner[32] || sequence.v || record_hash[32]
//        || public_key[32] || signature[64]

impl Encode for Update {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.sequence, out);
        self.record_hash.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for Update {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let update = Self {
            domain_id: DomainId::decode(input)?,
            owner: OwnerId::decode(input)?,
            sequence: u64::decode(input)?,
            record_hash: RecordHash::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        update.validate().map_err(ProtocolError::Validation)?;
        Ok(update)
    }
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Register(tx) => {
                out.push(tx_type::REGISTER);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::Update(tx) => {
                out.push(tx_type::UPDATE);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
        }
    }
}

impl Decode for Transaction {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let disc = codec::take_u8(input)?;
        let version = codec::take_u8(input)?;
        if version != TX_FORMAT_VERSION {
            // A v1 stream has no version byte: after the discriminator
            // it continues with `domain_id[0]`, which is never 0x02 for
            // a valid v1 DomainId derivation — but even the crafted
            // corner case lands on this same explicit error.
            return Err(ProtocolError::UnsupportedVersion(u64::from(version)));
        }
        Ok(match disc {
            tx_type::REGISTER => Self::Register(Register::decode(input)?),
            tx_type::UPDATE => Self::Update(Update::decode(input)?),
            value => {
                return Err(ProtocolError::UnknownDiscriminant {
                    kind: "transaction",
                    value,
                });
            }
        })
    }
}

/// The unsigned view of a transaction, used to build the signing
/// payload.
#[derive(Debug, Clone)]
pub enum UnsignedTransaction {
    /// See [`scone_core::Register`].
    Register {
        /// Claimed domain.
        domain_id: DomainId,
        /// Derived owner identity.
        owner: OwnerId,
        /// Ordering information.
        timestamp: u64,
        /// Registration proof (opaque).
        proof: Proof,
        /// Signer public key.
        public_key: PublicKey,
    },
    /// See [`scone_core::Update`].
    Update {
        /// Target domain.
        domain_id: DomainId,
        /// Derived owner identity.
        owner: OwnerId,
        /// Monotonic version of the record set.
        sequence: u64,
        /// Commitment to the DNS record set in the DHT.
        record_hash: RecordHash,
        /// Signer public key.
        public_key: PublicKey,
    },
}

impl From<&Transaction> for UnsignedTransaction {
    fn from(tx: &Transaction) -> Self {
        match tx {
            Transaction::Register(tx) => Self::Register {
                domain_id: tx.domain_id,
                owner: tx.owner,
                timestamp: tx.timestamp,
                proof: tx.proof.clone(),
                public_key: tx.public_key,
            },
            Transaction::Update(tx) => Self::Update {
                domain_id: tx.domain_id,
                owner: tx.owner,
                sequence: tx.sequence,
                record_hash: tx.record_hash,
                public_key: tx.public_key,
            },
        }
    }
}

impl Encode for UnsignedTransaction {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Register {
                domain_id,
                owner,
                timestamp,
                proof,
                public_key,
            } => {
                out.push(tx_type::REGISTER);
                out.push(TX_FORMAT_VERSION);
                domain_id.encode(out)?;
                owner.encode(out)?;
                varint::put_u64(*timestamp, out);
                proof.encode(out)?;
                public_key.encode(out)
            }
            Self::Update {
                domain_id,
                owner,
                sequence,
                record_hash,
                public_key,
            } => {
                out.push(tx_type::UPDATE);
                out.push(TX_FORMAT_VERSION);
                domain_id.encode(out)?;
                owner.encode(out)?;
                varint::put_u64(*sequence, out);
                record_hash.encode(out)?;
                public_key.encode(out)
            }
        }
    }
}

impl Decode for UnsignedTransaction {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let disc = codec::take_u8(input)?;
        let version = codec::take_u8(input)?;
        if version != TX_FORMAT_VERSION {
            return Err(ProtocolError::UnsupportedVersion(u64::from(version)));
        }
        Ok(match disc {
            tx_type::REGISTER => Self::Register {
                domain_id: DomainId::decode(input)?,
                owner: OwnerId::decode(input)?,
                timestamp: u64::decode(input)?,
                proof: Proof::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::UPDATE => Self::Update {
                domain_id: DomainId::decode(input)?,
                owner: OwnerId::decode(input)?,
                sequence: u64::decode(input)?,
                record_hash: RecordHash::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            value => {
                return Err(ProtocolError::UnknownDiscriminant {
                    kind: "transaction",
                    value,
                });
            }
        })
    }
}

/// Computes the exact bytes a signer must sign: the
/// `SCONE-TX-SIG-V1` prefix followed by the canonical encoding of the
/// transaction without its `signature` field (discriminator and format
/// version included).
///
/// ```text
/// signing_payload = "SCONE-TX-SIG-V1" || canonical_encode(tx_min_sig)
/// ```
///
/// Deterministic and pure: same transaction, same bytes, everywhere.
///
/// # Errors
///
/// Returns a [`ProtocolError`] if the unsigned view cannot be encoded
/// (core-invalid fields, oversized proof). Never panics.
pub fn signing_payload(tx: &Transaction) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(TX_SIG_PREFIX);
    UnsignedTransaction::from(tx).encode(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_complete, encode_to_vec};
    use crate::limits;
    use scone_core::DomainName;
    use scone_crypto::SigningKey;

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn signed_register() -> Register {
        let sk = key(1);
        let unsigned = Transaction::Register(Register::register_signed(
            domain_id(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        Register::register_signed(
            domain_id(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    fn signed_update() -> Update {
        let sk = key(1);
        let unsigned = Transaction::Update(Update::update_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        Update::update_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    #[test]
    fn register_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::Register(signed_register())).unwrap();
        assert_eq!(bytes[0], tx_type::REGISTER);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + domain_id + owner + timestamp (5-byte varint)
        // + empty proof (1) + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 32 + 32 + 5 + 1 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::Register(signed_register())
        );
    }

    #[test]
    fn update_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::Update(signed_update())).unwrap();
        assert_eq!(bytes[0], tx_type::UPDATE);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + domain_id + owner + sequence (1) + record_hash
        // + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 32 + 32 + 1 + 32 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::Update(signed_update())
        );
    }

    #[test]
    fn encoding_is_deterministic() {
        for tx in [
            Transaction::Register(signed_register()),
            Transaction::Update(signed_update()),
        ] {
            assert_eq!(encode_to_vec(&tx).unwrap(), encode_to_vec(&tx).unwrap());
        }
    }

    #[test]
    fn signing_payload_excludes_the_signature() {
        let sk = key(1);
        let unsigned = Transaction::Register(Register::register_signed(
            domain_id(),
            42,
            Proof::from_bytes(vec![0xaa; 4]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        // prefix + disc + version + domain + owner + timestamp + proof
        // + pk; no signature bytes.
        assert_eq!(
            payload.len(),
            TX_SIG_PREFIX.len() + 1 + 1 + 32 + 32 + 1 + 1 + 4 + 32
        );
        assert!(payload.starts_with(TX_SIG_PREFIX));
        // Changing the signature never changes the payload…
        let mut resigned = unsigned.clone();
        let sig = key(2).sign(&payload);
        if let Transaction::Register(tx) = &mut resigned {
            tx.signature = sig;
        }
        assert_eq!(signing_payload(&resigned).unwrap(), payload);
        // …but changing any signed field does.
        if let Transaction::Register(tx) = &mut resigned {
            tx.timestamp += 1;
        }
        assert_ne!(signing_payload(&resigned).unwrap(), payload);
    }

    #[test]
    fn signing_payload_is_what_verifies() {
        // End-to-end contract: sign(signing_payload(tx)) verifies
        // against the embedded key, tampering the payload fails.
        let sk = key(3);
        let unsigned = Transaction::Update(Update::update_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([7; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        let sig = sk.sign(&payload);
        assert!(sk.public_key().verify(&payload, &sig));
        let mut tampered = payload.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(!sk.public_key().verify(&tampered, &sig));
    }

    #[test]
    fn u64_max_register_timestamp_roundtrip() {
        let sk = key(1);
        let tx = Register::register_signed(
            domain_id(),
            u64::MAX,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(&[0]),
        );
        assert_eq!(
            decode_complete::<Transaction>(
                &encode_to_vec(&Transaction::Register(tx.clone())).unwrap()
            )
            .unwrap(),
            Transaction::Register(tx)
        );
    }

    #[test]
    fn u64_max_sequence_roundtrip() {
        let sk = key(1);
        let tx = Update::update_signed(
            domain_id(),
            u64::MAX,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            sk.sign(&[0]),
        );
        assert_eq!(
            decode_complete::<Transaction>(
                &encode_to_vec(&Transaction::Update(tx.clone())).unwrap()
            )
            .unwrap(),
            Transaction::Update(tx)
        );
    }

    #[test]
    fn v1_format_is_rejected_explicitly() {
        // Old-format Register: disc + domain_id + owner + timestamp +
        // proof, NO version byte and no key/signature.
        let mut old = Vec::new();
        old.push(tx_type::REGISTER);
        domain_id().encode(&mut old).unwrap();
        OwnerId::from_bytes([1; 32]).encode(&mut old).unwrap();
        varint::put_u64(1_700_000_000, &mut old);
        varint::put_u64(0, &mut old); // empty proof
        assert!(matches!(
            decode_complete::<Transaction>(&old),
            Err(ProtocolError::UnsupportedVersion(v)) if v != u64::from(TX_FORMAT_VERSION)
        ));
        // Any version byte other than 0x02 is an explicit version error.
        for bad in [0x00u8, 0x01, 0x03, 0xff] {
            let mut bytes = vec![tx_type::REGISTER, bad];
            bytes.extend_from_slice(&old[1..]);
            assert!(
                matches!(
                    decode_complete::<Transaction>(&bytes),
                    Err(ProtocolError::UnsupportedVersion(v)) if v == u64::from(bad)
                ),
                "version byte {bad:#04x}"
            );
        }
    }

    #[test]
    fn unknown_discriminant_rejected() {
        for disc in [0x00u8, 0x03, 0xff] {
            assert!(matches!(
                decode_complete::<Transaction>(&[disc, TX_FORMAT_VERSION]),
                Err(ProtocolError::UnknownDiscriminant {
                    kind: "transaction",
                    value
                }) if value == disc
            ));
        }
    }

    #[test]
    fn zero_sequence_rejected_on_encode_and_decode() {
        let sk = key(1);
        let raw = Update {
            domain_id: domain_id(),
            owner: test_support::owner_of(&sk.public_key()),
            sequence: 0,
            record_hash: RecordHash::from_bytes([9; 32]),
            public_key: sk.public_key(),
            signature: sk.sign(&[0]),
        };
        assert!(encode_to_vec(&Transaction::Update(raw.clone())).is_err());

        let mut bytes = Vec::new();
        bytes.push(tx_type::UPDATE);
        bytes.push(TX_FORMAT_VERSION);
        raw.domain_id.encode(&mut bytes).unwrap();
        raw.owner.encode(&mut bytes).unwrap();
        varint::put_u64(0, &mut bytes);
        raw.record_hash.encode(&mut bytes).unwrap();
        raw.public_key.encode(&mut bytes).unwrap();
        raw.signature.encode(&mut bytes).unwrap();
        assert!(decode_complete::<Transaction>(&bytes).is_err());
    }

    #[test]
    fn owner_key_binding_enforced_on_decode() {
        // owner field not derived from the embedded key: rejected.
        let sk = key(1);
        let mut bytes = Vec::new();
        bytes.push(tx_type::REGISTER);
        bytes.push(TX_FORMAT_VERSION);
        domain_id().encode(&mut bytes).unwrap();
        OwnerId::from_bytes([0xab; 32]).encode(&mut bytes).unwrap(); // forged
        varint::put_u64(1, &mut bytes);
        varint::put_u64(0, &mut bytes); // empty proof
        sk.public_key().encode(&mut bytes).unwrap();
        Signature::from_bytes([0; 64]).encode(&mut bytes).unwrap();
        assert!(decode_complete::<Transaction>(&bytes).is_err());
    }

    #[test]
    fn invalid_public_key_bytes_rejected_on_decode() {
        // y = 2 encoding does not decompress to a curve point.
        let mut not_on_curve = [0u8; 32];
        not_on_curve[0] = 0x02;
        let mut bytes = Vec::new();
        bytes.push(tx_type::REGISTER);
        bytes.push(TX_FORMAT_VERSION);
        domain_id().encode(&mut bytes).unwrap();
        OwnerId::from_bytes([0; 32]).encode(&mut bytes).unwrap();
        varint::put_u64(1, &mut bytes);
        varint::put_u64(0, &mut bytes);
        bytes.extend_from_slice(&not_on_curve);
        Signature::from_bytes([0; 64]).encode(&mut bytes).unwrap();
        assert!(matches!(
            decode_complete::<Transaction>(&bytes),
            Err(ProtocolError::InvalidTransactionKey)
        ));
    }

    #[test]
    fn proof_boundaries() {
        let mut tx = signed_register();
        tx.proof = Proof::from_bytes(vec![0xaa; limits::MAX_PROOF_LEN]);
        assert!(encode_to_vec(&Transaction::Register(tx.clone())).is_ok());

        tx.proof = Proof::from_bytes(vec![0xaa; limits::MAX_PROOF_LEN + 1]);
        assert!(matches!(
            encode_to_vec(&Transaction::Register(tx)),
            Err(ProtocolError::LimitExceeded("proof length"))
        ));
    }

    #[test]
    fn truncated_transaction_rejected() {
        let bytes = encode_to_vec(&Transaction::Update(signed_update())).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_complete::<Transaction>(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn corrupted_transaction_never_panics() {
        let bytes = encode_to_vec(&Transaction::Update(signed_update())).unwrap();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut corrupted = bytes.clone();
                corrupted[i] ^= mask;
                let _ = decode_complete::<Transaction>(&corrupted);
            }
        }
    }
}

/// Test-only re-derivation of the owner of a key (mirrors the private
/// `scone-core` helper, used by unit tests of this crate).
#[cfg(test)]
pub(crate) mod test_support {
    use scone_core::{OwnerId, PublicKeyRef};
    use scone_crypto::PublicKey;

    pub fn owner_of(public_key: &PublicKey) -> OwnerId {
        OwnerId::from_public_key_ref(&PublicKeyRef::from_public_key(&public_key.to_bytes()))
    }
}
