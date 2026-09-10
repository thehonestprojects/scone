//! Blockchain transactions.
//!
//! Since protocol version 2 (milestone M2), every transaction is
//! **signed**: it embeds the Ed25519 [`PublicKey`] (32 bytes) of its
//! signer and a 64-byte [`Signature`] over the canonical signing
//! payload defined by `scone-protocol`
//! (`SCONE-TX-SIG-V1` || canonical encoding of the transaction without
//! the signature — see `/docs/transactions.md`).
//!
//! The `owner` field is deliberately redundant with `public_key`: it is
//! ALWAYS recomputed from the embedded key and never trusted. A
//! transaction whose `owner` does not match the derivation of its own
//! `public_key` is invalid ([`Register::validate`] /
//! [`Update::validate`]) — the hard rule "recompute, never trust a
//! provided hash" applies to it.
//!
//! Layering: `scone-crypto` signs, `scone-protocol` encodes,
//! `scone-core` carries. This module holds pure types only: signature
//! *verification* does not happen here (it requires the canonical wire
//! encoding — see `scone_blockchain::validate_transaction`).

use scone_crypto::{PublicKey, Signature};

use crate::error::{Result, SconeError};
use crate::id::DomainId;
use crate::owner::{OwnerId, PublicKeyRef};

/// Opaque registration proof (reserved for the future proof of work).
///
/// Not implemented yet: `Register` validation ignores its content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Wraps raw proof bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Commitment to the full DNS record set of a domain.
///
/// Computed as
/// `BLAKE3-256("SCONE-RECORD-V1" || canonical_record_encoding)` by
/// `scone-protocol` (see `record_hash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordHash([u8; 32]);

impl RecordHash {
    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Recomputes the [`OwnerId`] bound to `public_key` (single source of
/// truth: the `scone-core` derivation, never duplicated).
pub(crate) fn owner_of(public_key: &PublicKey) -> OwnerId {
    OwnerId::from_public_key_ref(&PublicKeyRef::from_public_key(&public_key.to_bytes()))
}

/// Checks that `owner` is exactly the identity derived from
/// `public_key`.
fn check_owner_binding(owner: &OwnerId, public_key: &PublicKey) -> Result<()> {
    if *owner != owner_of(public_key) {
        return Err(SconeError::InvalidOwner(
            "owner does not match the embedded public key".into(),
        ));
    }
    Ok(())
}

/// Claims ownership of a domain (signed, format v2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Register {
    pub domain_id: DomainId,
    pub owner: OwnerId,
    /// Ordering information (Unix timestamp now; chain position later).
    pub timestamp: u64,
    /// Reserved for the registration proof of work (not yet implemented).
    pub proof: Proof,
    /// Ed25519 public key of the signer (32 bytes, embedded so the
    /// signature can be verified offline).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl Register {
    /// Builds a signed-shaped `Register`, recomputing `owner` from
    /// `public_key` (the caller-supplied owner is never trusted —
    /// there is none).
    ///
    /// The signature must have been produced over
    /// `scone_protocol::signing_payload` of the resulting transaction;
    /// this constructor does not verify it (pure types, no wire
    /// encoding here).
    #[must_use]
    pub fn register_signed(
        domain_id: DomainId,
        timestamp: u64,
        proof: Proof,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            domain_id,
            owner: owner_of(&public_key),
            timestamp,
            proof,
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidOwner`] when `owner` is not the
    /// identity derived from `public_key`. The `proof` content is not
    /// interpreted yet (future proof of work).
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// Publishes a new version of a domain's DNS data (signed, format v2).
///
/// On-chain: `domain_id + owner + sequence + record_hash`.
/// In the DHT: the full [`SignedDnsRecord`](crate::record::SignedDnsRecord)
/// whose hash must equal `record_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Update {
    pub domain_id: DomainId,
    pub owner: OwnerId,
    /// Monotonic version of the record set (ordering lives here, not
    /// in a timestamp, since format v2).
    pub sequence: u64,
    /// Commitment to the full DNS record set in the DHT.
    pub record_hash: RecordHash,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl Update {
    /// Builds a signed-shaped `Update`, recomputing `owner` from
    /// `public_key`.
    ///
    /// See [`Register::register_signed`] for the signature contract.
    #[must_use]
    pub fn update_signed(
        domain_id: DomainId,
        sequence: u64,
        record_hash: RecordHash,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            domain_id,
            owner: owner_of(&public_key),
            sequence,
            record_hash,
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// - [`SconeError::InvalidSequence`] if `sequence` is `0`;
    /// - [`SconeError::InvalidOwner`] when `owner` is not the identity
    ///   derived from `public_key`.
    pub fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(SconeError::InvalidSequence(0));
        }
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// A signed blockchain transaction (format v2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transaction {
    /// See [`Register`].
    Register(Register),
    /// See [`Update`].
    Update(Update),
}

impl Transaction {
    /// The domain this transaction applies to.
    pub fn domain_id(&self) -> DomainId {
        match self {
            Self::Register(tx) => tx.domain_id,
            Self::Update(tx) => tx.domain_id,
        }
    }

    /// The declared owner (always re-derived from
    /// [`Transaction::public_key`] by [`Transaction::validate`]).
    pub fn owner(&self) -> OwnerId {
        match self {
            Self::Register(tx) => tx.owner,
            Self::Update(tx) => tx.owner,
        }
    }

    /// The embedded signer public key.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Register(tx) => &tx.public_key,
            Self::Update(tx) => &tx.public_key,
        }
    }

    /// The embedded signature.
    pub fn signature(&self) -> &Signature {
        match self {
            Self::Register(tx) => &tx.signature,
            Self::Update(tx) => &tx.signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// - [`SconeError::InvalidSequence`] for an `Update` with a zero
    ///   sequence;
    /// - [`SconeError::InvalidOwner`] when `owner` does not match the
    ///   embedded public key.
    ///
    /// This does NOT verify the signature itself: that requires the
    /// canonical wire encoding (`scone_blockchain::validate_transaction`).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Register(tx) => tx.validate(),
            Self::Update(tx) => tx.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::DomainName;
    use scone_crypto::SigningKey;

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn placeholder_signature() -> Signature {
        Signature::from_bytes([0u8; 64])
    }

    fn register() -> Register {
        Register::register_signed(
            domain_id(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            key(1).public_key(),
            placeholder_signature(),
        )
    }

    fn update() -> Update {
        Update::update_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([9; 32]),
            key(1).public_key(),
            placeholder_signature(),
        )
    }

    #[test]
    fn register_validates_with_any_proof_content() {
        assert!(Transaction::Register(register()).validate().is_ok());
    }

    #[test]
    fn update_validates() {
        assert!(Transaction::Update(update()).validate().is_ok());
    }

    #[test]
    fn constructors_recompute_owner_from_the_key() {
        let sk = key(7);
        let reg = Register::register_signed(
            domain_id(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(reg.owner, owner_of(&sk.public_key()));

        let upd = Update::update_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([1; 32]),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(upd.owner, reg.owner);
    }

    #[test]
    fn owner_key_mismatch_is_invalid() {
        let sk_a = key(1);
        let sk_b = key(2);
        let mut reg = Register::register_signed(
            domain_id(),
            1,
            Proof::from_bytes(Vec::new()),
            sk_a.public_key(),
            placeholder_signature(),
        );
        // Forged owner: not the derivation of the embedded key.
        reg.owner = owner_of(&sk_b.public_key());
        assert!(matches!(
            Transaction::Register(reg.clone()).validate(),
            Err(SconeError::InvalidOwner(_))
        ));

        let mut upd = Update::update_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([1; 32]),
            sk_a.public_key(),
            placeholder_signature(),
        );
        upd.owner = owner_of(&sk_b.public_key());
        assert!(matches!(
            Transaction::Update(upd).validate(),
            Err(SconeError::InvalidOwner(_))
        ));
    }

    #[test]
    fn update_zero_sequence_is_invalid() {
        let mut tx = update();
        tx.sequence = 0;
        assert!(matches!(tx.validate(), Err(SconeError::InvalidSequence(0))));
        assert!(matches!(
            Transaction::Update(tx).validate(),
            Err(SconeError::InvalidSequence(0))
        ));
    }

    #[test]
    fn transaction_accessors() {
        let reg = Transaction::Register(register());
        let upd = Transaction::Update(update());
        assert_eq!(reg.domain_id(), domain_id());
        assert_eq!(upd.domain_id(), domain_id());
        assert_eq!(reg.owner(), owner_of(&key(1).public_key()));
        assert_eq!(upd.owner(), owner_of(&key(1).public_key()));
        assert_eq!(reg.public_key(), &key(1).public_key());
        assert_eq!(upd.signature(), &placeholder_signature());
    }
}
