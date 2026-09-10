//! Wire encoding of blockchain transactions.
//!
//! ```text
//! Transaction = disc u8 || payload
//!   0x01 Register
//!   0x02 Update
//! ```
//!
//! Transactions carry only compact references (`DomainId`, `OwnerId`,
//! `RecordHash`); the full DNS payload stays in the DHT (see
//! `/docs/protocol.md`).

use scone_core::{DomainId, OwnerId, Proof, RecordHash, Register, Transaction, Update};

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

// Register = domain_id[32] || owner[32] || timestamp.v || proof

impl Encode for Register {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.timestamp, out);
        self.proof.encode(out)
    }
}

impl Decode for Register {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            domain_id: DomainId::decode(input)?,
            owner: OwnerId::decode(input)?,
            timestamp: u64::decode(input)?,
            proof: Proof::decode(input)?,
        })
    }
}

// Update = domain_id[32] || owner[32] || sequence.v || record_hash[32] || timestamp.v

impl Encode for Update {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.sequence, out);
        self.record_hash.encode(out)?;
        varint::put_u64(self.timestamp, out);
        Ok(())
    }
}

impl Decode for Update {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let update = Self {
            domain_id: DomainId::decode(input)?,
            owner: OwnerId::decode(input)?,
            sequence: u64::decode(input)?,
            record_hash: RecordHash::decode(input)?,
            timestamp: u64::decode(input)?,
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
                tx.encode(out)
            }
            Self::Update(tx) => {
                out.push(tx_type::UPDATE);
                tx.encode(out)
            }
        }
    }
}

impl Decode for Transaction {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(match codec::take_u8(input)? {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_complete, encode_to_vec};
    use scone_core::DomainName;

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn register() -> Register {
        Register {
            domain_id: domain_id(),
            owner: OwnerId::from_bytes([1; 32]),
            timestamp: 1_700_000_000,
            proof: Proof::from_bytes(Vec::new()),
        }
    }

    fn update() -> Update {
        Update {
            domain_id: domain_id(),
            owner: OwnerId::from_bytes([1; 32]),
            sequence: 1,
            record_hash: RecordHash::from_bytes([9; 32]),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn register_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::Register(register())).unwrap();
        assert_eq!(bytes[0], tx_type::REGISTER);
        // disc + domain_id + owner + timestamp (5-byte varint) + empty proof.
        assert_eq!(bytes.len(), 1 + 32 + 32 + 5 + 1);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::Register(register())
        );
    }

    #[test]
    fn update_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::Update(update())).unwrap();
        assert_eq!(bytes[0], tx_type::UPDATE);
        // disc + domain_id + owner + sequence (1) + record_hash + timestamp (5).
        assert_eq!(bytes.len(), 1 + 32 + 32 + 1 + 32 + 5);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::Update(update())
        );
    }

    #[test]
    fn encoding_is_deterministic() {
        for tx in [
            Transaction::Register(register()),
            Transaction::Update(update()),
        ] {
            assert_eq!(encode_to_vec(&tx).unwrap(), encode_to_vec(&tx).unwrap());
        }
    }

    #[test]
    fn u64_max_sequence_and_timestamp_roundtrip() {
        let mut tx = update();
        tx.sequence = u64::MAX;
        tx.timestamp = u64::MAX;
        assert_eq!(
            decode_complete::<Transaction>(
                &encode_to_vec(&Transaction::Update(tx.clone())).unwrap()
            )
            .unwrap(),
            Transaction::Update(tx)
        );
    }

    #[test]
    fn zero_timestamp_allowed() {
        let mut tx = register();
        tx.timestamp = 0;
        assert_eq!(
            decode_complete::<Transaction>(
                &encode_to_vec(&Transaction::Register(tx.clone())).unwrap()
            )
            .unwrap(),
            Transaction::Register(tx)
        );
    }

    #[test]
    fn zero_sequence_rejected_on_encode_and_decode() {
        let mut tx = update();
        tx.sequence = 0;
        assert!(encode_to_vec(&Transaction::Update(tx.clone())).is_err());

        let mut bytes = Vec::new();
        bytes.push(tx_type::UPDATE);
        tx.domain_id.encode(&mut bytes).unwrap();
        tx.owner.encode(&mut bytes).unwrap();
        varint::put_u64(0, &mut bytes);
        tx.record_hash.encode(&mut bytes).unwrap();
        varint::put_u64(0, &mut bytes);
        assert!(decode_complete::<Transaction>(&bytes).is_err());
    }

    #[test]
    fn unknown_discriminant_rejected() {
        for disc in [0x00u8, 0x03, 0xff] {
            assert!(matches!(
                decode_complete::<Transaction>(&[disc]),
                Err(ProtocolError::UnknownDiscriminant {
                    kind: "transaction",
                    value
                }) if value == disc
            ));
        }
    }

    #[test]
    fn empty_proof_roundtrip() {
        let bytes = encode_to_vec(&Transaction::Register(register())).unwrap();
        assert_eq!(*bytes.last().unwrap(), 0x00);
    }

    #[test]
    fn proof_boundaries() {
        let mut tx = register();
        tx.proof = Proof::from_bytes(vec![0xaa; crate::limits::MAX_PROOF_LEN]);
        assert!(encode_to_vec(&Transaction::Register(tx.clone())).is_ok());

        tx.proof = Proof::from_bytes(vec![0xaa; crate::limits::MAX_PROOF_LEN + 1]);
        assert!(matches!(
            encode_to_vec(&Transaction::Register(tx)),
            Err(ProtocolError::LimitExceeded("proof length"))
        ));
    }

    #[test]
    fn truncated_transaction_rejected() {
        let bytes = encode_to_vec(&Transaction::Update(update())).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_complete::<Transaction>(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn corrupted_transaction_never_panics() {
        let bytes = encode_to_vec(&Transaction::Update(update())).unwrap();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut corrupted = bytes.clone();
                corrupted[i] ^= mask;
                let _ = decode_complete::<Transaction>(&corrupted);
            }
        }
    }
}
