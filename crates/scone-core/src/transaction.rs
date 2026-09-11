//! Blockchain transactions.
//!
//! Every transaction is **signed** (since the genesis of the deployed
//! format, milestone M2): it embeds the Ed25519 [`PublicKey`] (32
//! bytes) of its signer and a 64-byte [`Signature`] over the canonical
//! signing payload defined by `scone-protocol`
//! (`SCONE-TX-SIG-V1` || canonical encoding of the transaction without
//! the signature — see `/docs/technical/transactions.md`).
//!
//! The `owner` field is deliberately redundant with `public_key`: it is
//! ALWAYS recomputed from the embedded key and never trusted. A
//! transaction whose `owner` does not match the derivation of its own
//! `public_key` is invalid ([`RegisterDomain::validate`] /
//! [`UpdateDomain::validate`]) — the hard rule "recompute, never trust a
//! provided hash" applies to it.
//!
//! Layering: `scone-crypto` signs, `scone-protocol` encodes,
//! `scone-core` carries. This module holds pure types only: signature
//! *verification* does not happen here (it requires the canonical wire
//! encoding — see `scone_blockchain::validate_transaction`).

use scone_crypto::{PublicKey, Signature};

use crate::error::{Result, SconeError};
use crate::id::{DomainId, TldId};
use crate::name::DomainName;
use crate::owner::{OwnerId, PublicKeyRef};

/// Opaque registration proof (reserved for the future proof of work).
///
/// Not implemented yet: `RegisterDomain` validation ignores its content.
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

/// Claims ownership of a domain (signed).
///
/// Since M7b the transaction carries the **canonical domain name** in
/// clear ([`DomainName`], wire-visible), alongside its derived
/// [`DomainId`]: the chain stays self-describing and name → id
/// consistency is verified on decode. The id remains the consensus
/// identity; the name is display/ordering metadata carried by the
/// transaction that claims it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterDomain {
    /// Claimed domain, by canonical name (wire-visible).
    pub name: DomainName,
    /// Derived identity of `name` (recomputed, never trusted — see
    /// [`RegisterDomain::validate`]).
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

impl RegisterDomain {
    /// Builds a signed-shaped `RegisterDomain`, recomputing `owner` from
    /// `public_key` (the caller-supplied owner is never trusted —
    /// there is none).
    ///
    /// The signature must have been produced over
    /// `scone_protocol::signing_payload` of the resulting transaction;
    /// this constructor does not verify it (pure types, no wire
    /// encoding here).
    #[must_use]
    pub fn register_domain_signed(
        name: DomainName,
        timestamp: u64,
        proof: Proof,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            domain_id: DomainId::from_name(&name),
            owner: owner_of(&public_key),
            name,
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
    /// - [`SconeError::InvalidOwner`] when `owner` is not the identity
    ///   derived from `public_key`;
    /// - [`SconeError::InvalidDomain`] when `domain_id` is not the
    ///   derivation of `name`.
    ///
    /// The `proof` content is not interpreted yet (future proof of
    /// work).
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)?;
        if self.domain_id != DomainId::from_name(&self.name) {
            return Err(SconeError::InvalidDomain(format!(
                "domain_id is not the derivation of the carried name {:?}",
                self.name.canonical()
            )));
        }
        Ok(())
    }
}

/// Publishes a new version of a domain's DNS data (signed).
///
/// On-chain: `domain_id + owner + sequence + record_hash`.
/// In the DHT: the full [`SignedDnsRecord`](crate::record::SignedDnsRecord)
/// whose hash must equal `record_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpdateDomain {
    pub domain_id: DomainId,
    pub owner: OwnerId,
    /// Monotonic version of the record set (ordering lives here, not
    /// in a timestamp).
    pub sequence: u64,
    /// Commitment to the full DNS record set in the DHT.
    pub record_hash: RecordHash,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl UpdateDomain {
    /// Builds a signed-shaped `UpdateDomain`, recomputing `owner` from
    /// `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn update_domain_signed(
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

/// Claims ownership of a top-level domain (M7a — TLD registry).
///
/// Mirrors [`RegisterDomain`] but targets a [`TldId`] instead of a
/// [`DomainId`]: registering the TLD `uip` is an on-chain claim over
/// the *namespace* `*.uip`, a different object from any `name.uip`
/// domain. The id spaces are disjoint by derivation
/// (`SCONE-TLD-V1` vs `SCONE-DOMAIN-V1`), so no cross-squatting is
/// possible.
///
/// Like every signed transaction: `owner` is ALWAYS recomputed from
/// the embedded `public_key` (never trusted — see
/// [`RegisterDomain::register_domain_signed`]); the `signature` must cover the
/// canonical signing payload of `scone-protocol`; `validate` here
/// only checks the pure invariants, not the signature itself.
///
/// Since M7b the type is part of the [`Transaction`] enum and of the
/// wire format (discriminator `0x03`, see `scone-protocol`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterTld {
    /// The claimed TLD (namespace id, disjoint from any `DomainId`).
    pub tld_id: TldId,
    /// Recomputed owner identity (never trusted from input).
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

impl RegisterTld {
    /// Builds a signed-shaped `RegisterTld`, recomputing `owner` from
    /// `public_key` (the caller-supplied owner is never trusted —
    /// there is none).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn register_tld_signed(
        tld_id: TldId,
        timestamp: u64,
        proof: Proof,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            tld_id,
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

/// A signed blockchain transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transaction {
    /// See [`RegisterDomain`].
    RegisterDomain(RegisterDomain),
    /// See [`UpdateDomain`].
    UpdateDomain(UpdateDomain),
    /// See [`RegisterTld`] (TLD registry, M7).
    RegisterTld(RegisterTld),
}

impl Transaction {
    /// The declared owner (always re-derived from
    /// [`Transaction::public_key`] by [`Transaction::validate`]).
    pub fn owner(&self) -> OwnerId {
        match self {
            Self::RegisterDomain(tx) => tx.owner,
            Self::UpdateDomain(tx) => tx.owner,
            Self::RegisterTld(tx) => tx.owner,
        }
    }

    /// The embedded signer public key.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::RegisterDomain(tx) => &tx.public_key,
            Self::UpdateDomain(tx) => &tx.public_key,
            Self::RegisterTld(tx) => &tx.public_key,
        }
    }

    /// The embedded signature.
    pub fn signature(&self) -> &Signature {
        match self {
            Self::RegisterDomain(tx) => &tx.signature,
            Self::UpdateDomain(tx) => &tx.signature,
            Self::RegisterTld(tx) => &tx.signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// - [`SconeError::InvalidSequence`] for an `UpdateDomain` with a zero
    ///   sequence;
    /// - [`SconeError::InvalidDomain`] for a `RegisterDomain` whose
    ///   `domain_id` does not match its carried name;
    /// - [`SconeError::InvalidOwner`] when `owner` does not match the
    ///   embedded public key.
    ///
    /// This does NOT verify the signature itself: that requires the
    /// canonical wire encoding (`scone_blockchain::validate_transaction`).
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::RegisterDomain(tx) => tx.validate(),
            Self::UpdateDomain(tx) => tx.validate(),
            Self::RegisterTld(tx) => tx.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::{DomainName, TldName};
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

    fn name() -> DomainName {
        DomainName::new("example.uip").unwrap()
    }

    fn register() -> RegisterDomain {
        RegisterDomain::register_domain_signed(
            name(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            key(1).public_key(),
            placeholder_signature(),
        )
    }

    fn update() -> UpdateDomain {
        UpdateDomain::update_domain_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([9; 32]),
            key(1).public_key(),
            placeholder_signature(),
        )
    }

    #[test]
    fn register_validates_with_any_proof_content() {
        assert!(Transaction::RegisterDomain(register()).validate().is_ok());
    }

    #[test]
    fn update_validates() {
        assert!(Transaction::UpdateDomain(update()).validate().is_ok());
    }

    #[test]
    fn constructors_recompute_owner_from_the_key() {
        let sk = key(7);
        let reg = RegisterDomain::register_domain_signed(
            name(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(reg.owner, owner_of(&sk.public_key()));

        let upd = UpdateDomain::update_domain_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([1; 32]),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(upd.owner, reg.owner);
    }

    #[test]
    fn register_derives_domain_id_from_the_carried_name() {
        let reg = register();
        assert_eq!(reg.domain_id, DomainId::from_name(&reg.name));
        assert_eq!(reg.name.canonical(), "example.uip");
    }

    #[test]
    fn register_name_id_mismatch_is_invalid() {
        let mut reg = register();
        reg.domain_id = DomainId::from_name(&DomainName::new("other.uip").unwrap());
        assert!(matches!(
            Transaction::RegisterDomain(reg).validate(),
            Err(SconeError::InvalidDomain(_))
        ));
    }

    #[test]
    fn owner_key_mismatch_is_invalid() {
        let sk_a = key(1);
        let sk_b = key(2);
        let mut reg = RegisterDomain::register_domain_signed(
            name(),
            1,
            Proof::from_bytes(Vec::new()),
            sk_a.public_key(),
            placeholder_signature(),
        );
        // Forged owner: not the derivation of the embedded key.
        reg.owner = owner_of(&sk_b.public_key());
        assert!(matches!(
            Transaction::RegisterDomain(reg.clone()).validate(),
            Err(SconeError::InvalidOwner(_))
        ));

        let mut upd = UpdateDomain::update_domain_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([1; 32]),
            sk_a.public_key(),
            placeholder_signature(),
        );
        upd.owner = owner_of(&sk_b.public_key());
        assert!(matches!(
            Transaction::UpdateDomain(upd).validate(),
            Err(SconeError::InvalidOwner(_))
        ));
    }

    #[test]
    fn update_zero_sequence_is_invalid() {
        let mut tx = update();
        tx.sequence = 0;
        assert!(matches!(tx.validate(), Err(SconeError::InvalidSequence(0))));
        assert!(matches!(
            Transaction::UpdateDomain(tx).validate(),
            Err(SconeError::InvalidSequence(0))
        ));
    }

    #[test]
    fn transaction_accessors() {
        let reg = Transaction::RegisterDomain(register());
        let upd = Transaction::UpdateDomain(update());
        assert_eq!(reg.owner(), owner_of(&key(1).public_key()));
        assert_eq!(upd.owner(), owner_of(&key(1).public_key()));
        assert_eq!(reg.public_key(), &key(1).public_key());
        assert_eq!(upd.signature(), &placeholder_signature());
    }

    // --- RegisterTld (M7a) ---

    fn tld_id() -> TldId {
        TldId::from_tld(&TldName::new("uip").unwrap())
    }

    fn register_tld() -> RegisterTld {
        RegisterTld::register_tld_signed(
            tld_id(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            key(1).public_key(),
            placeholder_signature(),
        )
    }

    #[test]
    fn register_tld_validates_with_any_proof_content() {
        assert!(register_tld().validate().is_ok());
    }

    #[test]
    fn register_tld_constructor_recomputes_owner_from_the_key() {
        let sk = key(9);
        let tx = RegisterTld::register_tld_signed(
            tld_id(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(tx.owner, owner_of(&sk.public_key()));
    }

    #[test]
    fn register_tld_owner_key_mismatch_is_invalid() {
        let sk_a = key(1);
        let sk_b = key(2);
        let mut tx = RegisterTld::register_tld_signed(
            tld_id(),
            1,
            Proof::from_bytes(Vec::new()),
            sk_a.public_key(),
            placeholder_signature(),
        );
        // Forged owner: not the derivation of the embedded key.
        tx.owner = owner_of(&sk_b.public_key());
        assert!(matches!(tx.validate(), Err(SconeError::InvalidOwner(_))));
    }

    #[test]
    fn register_tld_shares_owner_identity_with_domain_register() {
        // Same key ⇒ same owner on both registries: one identity can
        // hold domains and TLDs.
        let reg = register();
        let tld_reg = register_tld();
        assert_eq!(reg.owner, tld_reg.owner);
    }

    #[test]
    fn register_tld_target_is_a_tld_id_not_a_domain_id() {
        let tx = register_tld();
        // The claimed namespace id is the TLD derivation of "uip"…
        assert_eq!(tx.tld_id, tld_id());
        // …and is disjoint from any domain derivation.
        assert_ne!(tx.tld_id.as_bytes(), domain_id().as_bytes());
    }
}
