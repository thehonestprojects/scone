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
    use scone_crypto::{Signature, SigningKey};

    fn domain_id(name: &str) -> DomainId {
        DomainId::from_name(&DomainName::new(name).unwrap())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn register() -> Register {
        let sk = key(1);
        Register::register_signed(
            domain_id("example.uip"),
            1_700_000_000,
            Proof::from_bytes(vec![0xaa; 4]),
            sk.public_key(),
            sk.sign(b"fixture"),
        )
    }

    fn update() -> Update {
        let sk = key(1);
        Update::update_signed(
            domain_id("example.uip"),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            sk.sign(b"fixture"),
        )
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
        let _ = other_owner;
        // Owner-forged Registers cannot be encoded anymore (Encode
        // validates the owner/pk binding — docs/transactions.md) ; TxId
        // sensitivity to `owner` is asserted at the wire level instead.
        let raw = scone_protocol::encode_to_vec(&Transaction::Register(register())).unwrap();
        let mut forged = raw.clone();
        forged[2 + 32..2 + 64].copy_from_slice(OwnerId::from_bytes([2; 32]).as_bytes());
        assert!(
            scone_protocol::decode_complete::<Transaction>(&forged).is_err(),
            "owner-forged Register must be rejected on decode"
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

        let mut other_key = register();
        other_key.public_key = key(2).public_key();
        other_key.owner = crate::validate::owner_from_public_key(&key(2).public_key());
        assert_ne!(
            transaction_id(&Transaction::Register(other_key)).unwrap(),
            base
        );

        let mut other_signature = register();
        other_key_signature_bump(&mut other_signature);
        assert_ne!(
            transaction_id(&Transaction::Register(other_signature)).unwrap(),
            base
        );
    }

    /// Flips one byte of the signature in place (test helper).
    fn other_key_signature_bump(register: &mut Register) {
        let mut raw = register.signature.to_bytes();
        raw[63] ^= 0x01;
        register.signature = Signature::from_bytes(raw);
    }

    #[test]
    fn update_field_sensitivity() {
        let base = transaction_id(&Transaction::Update(update())).unwrap();

        // Note: owner alone cannot change without the key (binding
        // enforced at encode); key+owner together is the meaningful
        // variation, checked below.
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

        let mut other_key = update();
        other_key.public_key = key(2).public_key();
        other_key.owner = crate::validate::owner_from_public_key(&key(2).public_key());
        assert_ne!(
            transaction_id(&Transaction::Update(other_key)).unwrap(),
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
