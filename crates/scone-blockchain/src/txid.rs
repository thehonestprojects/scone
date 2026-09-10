//! Transaction identity.

use scone_core::Transaction;
use scone_protocol::codec::encode_to_vec;

use crate::error::Result;

/// Domain-separation prefix for [`transaction_id`].
pub const TX_ID_VERSION: &[u8] = b"SCONE-TX-V1";

/// Deterministic 32-byte identifier of a blockchain transaction.
///
/// Computed as:
///
/// ```text
/// TxId = BLAKE3-256("SCONE-TX-V1" || canonical_encode(Transaction))
/// ```
///
/// A transaction is identified **by content**: two transactions with
/// identical canonical encodings share the same `TxId` everywhere, and
/// any field change produces a different id. No local timestamp and no
/// non-canonical value ever enters the computation; there is no
/// dependency on storage or network.
///
/// Identical-content replays are not rejected here: they are naturally
/// impossible to apply twice (see [`crate::ChainState`]: double
/// `Register` or sequence replay fail the state rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes (decoded from storage or the wire).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for TxId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Computes the deterministic identifier of `tx`.
///
/// # Errors
///
/// Returns [`BlockchainError::Protocol`](crate::BlockchainError) if `tx`
/// cannot be canonically encoded (core-invalid fields, oversized
/// proof). Never panics.
pub fn transaction_id(tx: &Transaction) -> Result<TxId> {
    let encoded = encode_to_vec(tx)?;
    Ok(TxId(scone_crypto::hash256(&[TX_ID_VERSION, &encoded])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BlockchainError;
    use scone_core::{DomainId, DomainName, OwnerId, Proof, RecordHash, Register, Update};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    fn register() -> Register {
        Register {
            domain_id: domain_id("example.uip"),
            owner: OwnerId::from_bytes([1; 32]),
            timestamp: 1_700_000_000,
            proof: Proof::from_bytes(vec![0xaa; 4]),
        }
    }

    fn update() -> Update {
        Update {
            domain_id: domain_id("example.uip"),
            owner: OwnerId::from_bytes([1; 32]),
            sequence: 1,
            record_hash: RecordHash::from_bytes([9; 32]),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn deterministic() {
        for tx in [
            Transaction::Register(register()),
            Transaction::Update(update()),
        ] {
            assert_eq!(transaction_id(&tx).unwrap(), transaction_id(&tx).unwrap());
        }
    }

    #[test]
    fn matches_documented_formula() {
        for tx in [
            Transaction::Register(register()),
            Transaction::Update(update()),
        ] {
            let encoded = encode_to_vec(&tx).unwrap();
            let expected = scone_crypto::hash256(&[TX_ID_VERSION, &encoded]);
            assert_eq!(*transaction_id(&tx).unwrap().as_bytes(), expected);
        }
    }

    #[test]
    fn register_and_update_differ() {
        assert_ne!(
            transaction_id(&Transaction::Register(register())).unwrap(),
            transaction_id(&Transaction::Update(update())).unwrap()
        );
    }

    #[test]
    fn distinct_domains_differ() {
        let mut tx = register();
        tx.domain_id = domain_id("other.uip");
        assert_ne!(
            transaction_id(&Transaction::Register(tx)).unwrap(),
            transaction_id(&Transaction::Register(register())).unwrap()
        );
    }

    #[test]
    fn register_field_sensitivity() {
        let base = transaction_id(&Transaction::Register(register())).unwrap();

        let mut other_owner = register();
        other_owner.owner = OwnerId::from_bytes([2; 32]);
        assert_ne!(
            transaction_id(&Transaction::Register(other_owner)).unwrap(),
            base
        );

        let mut other_timestamp = register();
        other_timestamp.timestamp += 1;
        assert_ne!(
            transaction_id(&Transaction::Register(other_timestamp)).unwrap(),
            base
        );

        let mut other_proof = register();
        other_proof.proof = Proof::from_bytes(vec![0xbb; 4]);
        assert_ne!(
            transaction_id(&Transaction::Register(other_proof)).unwrap(),
            base
        );
    }

    #[test]
    fn update_field_sensitivity() {
        let base = transaction_id(&Transaction::Update(update())).unwrap();

        let mut other_owner = update();
        other_owner.owner = OwnerId::from_bytes([2; 32]);
        assert_ne!(
            transaction_id(&Transaction::Update(other_owner)).unwrap(),
            base
        );

        let mut other_sequence = update();
        other_sequence.sequence = 2;
        assert_ne!(
            transaction_id(&Transaction::Update(other_sequence)).unwrap(),
            base
        );

        let mut other_hash = update();
        other_hash.record_hash = RecordHash::from_bytes([8; 32]);
        assert_ne!(
            transaction_id(&Transaction::Update(other_hash)).unwrap(),
            base
        );

        let mut other_timestamp = update();
        other_timestamp.timestamp += 1;
        assert_ne!(
            transaction_id(&Transaction::Update(other_timestamp)).unwrap(),
            base
        );
    }

    #[test]
    fn invalid_transaction_is_an_error_not_a_panic() {
        let mut tx = update();
        tx.sequence = 0;
        assert!(matches!(
            transaction_id(&Transaction::Update(tx)),
            Err(BlockchainError::Protocol(_))
        ));
    }

    #[test]
    fn bytes_roundtrip_and_map_key() {
        let id = transaction_id(&Transaction::Register(register())).unwrap();
        assert_eq!(TxId::from_bytes(*id.as_bytes()), id);
        assert_eq!(TxId::from(*id.as_bytes()), id);

        let mut set = std::collections::HashSet::new();
        set.insert(id);
        assert!(set.contains(&transaction_id(&Transaction::Register(register())).unwrap()));
        assert!(!set.contains(&transaction_id(&Transaction::Update(update())).unwrap()));
    }
}
