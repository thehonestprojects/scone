//! Cryptographic validation of signed transactions (format v2).
//!
//! The hard rule of the project lives here: **recompute, never trust
//! a provided value**. For every transaction:
//!
//! 1. the `owner` field must equal `OwnerId::from(public_key)`
//!    (recomputed from the embedded key — also enforced by
//!    `scone-core::Transaction::validate`, defence in depth);
//! 2. the signature must verify with `verify_strict` over the
//!    canonical signing payload
//!    (`"SCONE-TX-SIG-V1" || canonical_encode(tx_without_signature)`),
//!    recomputed from scratch — never taken from the tx or a peer.
//!
//! No panic on hostile input; every failure is a typed
//! [`BlockchainError`].

use scone_core::{OwnerId, PublicKeyRef, Transaction};
use scone_protocol::signing_payload;

use crate::error::{BlockchainError, Result};

/// Recomputes the [`OwnerId`] bound to `public_key`.
#[must_use]
pub fn owner_from_public_key(public_key: &scone_crypto::PublicKey) -> OwnerId {
    OwnerId::from_public_key_ref(&PublicKeyRef::from_public_key(&public_key.to_bytes()))
}

/// Full validation of a signed transaction: core invariants, owner/key
/// binding (recomputed), signature over the recomputed canonical
/// payload (`verify_strict`).
///
/// # Errors
///
/// - [`BlockchainError::Core`] for a core invariant violation (zero
///   sequence, owner/key mismatch already caught by `scone-core`);
/// - [`BlockchainError::OwnerKeyMismatch`] if the recomputed
///   owner does not match `tx.owner`;
/// - [`BlockchainError::InvalidSignature`] if the signature does not
///   verify.
///
/// Never panics.
pub fn validate_transaction(tx: &Transaction) -> Result<()> {
    // Owner/key binding first — the recomputed value always wins over
    // the provided one (core `validate` re-checks it too: defence in
    // depth).
    let expected_owner = owner_from_public_key(tx.public_key());
    if tx.owner() != expected_owner {
        return Err(BlockchainError::OwnerKeyMismatch);
    }
    tx.validate()?;
    let payload = signing_payload(tx)?;
    if !tx.public_key().verify(&payload, tx.signature()) {
        return Err(BlockchainError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_core::{DomainId, DomainName, Proof, RecordHash, Register, Update};
    use scone_crypto::{Signature, SigningKey};

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn signed_register(sk: &SigningKey) -> Transaction {
        let unsigned = Transaction::Register(Register::register_signed(
            domain_id(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        Transaction::Register(Register::register_signed(
            domain_id(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(&payload),
        ))
    }

    fn signed_update(sk: &SigningKey, sequence: u64) -> Transaction {
        let unsigned = Transaction::Update(Update::update_signed(
            domain_id(),
            sequence,
            RecordHash::from_bytes([sequence as u8; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        Transaction::Update(Update::update_signed(
            domain_id(),
            sequence,
            RecordHash::from_bytes([sequence as u8; 32]),
            sk.public_key(),
            sk.sign(&payload),
        ))
    }

    #[test]
    fn valid_transactions_pass() {
        let sk = SigningKey::from_bytes([1; 32]);
        assert!(validate_transaction(&signed_register(&sk)).is_ok());
        assert!(validate_transaction(&signed_update(&sk, 1)).is_ok());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let sk = SigningKey::from_bytes([1; 32]);
        let mut tx = signed_register(&sk);
        if let Transaction::Register(r) = &mut tx {
            let mut raw = r.signature.to_bytes();
            raw[0] ^= 0x01;
            r.signature = Signature::from_bytes(raw);
        }
        assert_eq!(
            validate_transaction(&tx),
            Err(BlockchainError::InvalidSignature)
        );
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let sk = SigningKey::from_bytes([1; 32]);
        let other = SigningKey::from_bytes([2; 32]);
        let mut tx = signed_register(&sk);
        // Sign with another key, keep the original public_key/owner.
        let payload = signing_payload(&tx).unwrap();
        if let Transaction::Register(r) = &mut tx {
            r.signature = other.sign(&payload);
        }
        assert_eq!(
            validate_transaction(&tx),
            Err(BlockchainError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        // A field protected by the signature is modified after
        // signing: the recomputed payload no longer matches.
        let sk = SigningKey::from_bytes([1; 32]);
        let mut tx = signed_update(&sk, 1);
        if let Transaction::Update(u) = &mut tx {
            u.record_hash = RecordHash::from_bytes([0xee; 32]);
        }
        assert_eq!(
            validate_transaction(&tx),
            Err(BlockchainError::InvalidSignature)
        );
    }

    #[test]
    fn owner_not_derived_from_key_is_rejected() {
        let sk = SigningKey::from_bytes([1; 32]);
        let other = SigningKey::from_bytes([2; 32]);
        let mut tx = signed_register(&sk);
        if let Transaction::Register(r) = &mut tx {
            r.public_key = other.public_key();
        }
        // owner still the one derived from sk: mismatch. Signature
        // rebuilt "consistently" with the swapped key, old owner kept.
        let payload = signing_payload(&tx).unwrap();
        if let Transaction::Register(r) = &mut tx {
            r.signature = other.sign(&payload);
        }
        // owner != from(other.public_key) → rejected before signature.
        assert_eq!(
            validate_transaction(&tx),
            Err(BlockchainError::OwnerKeyMismatch)
        );
    }
}
