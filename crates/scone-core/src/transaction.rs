//! Blockchain transactions.
//!
//! Every transaction is **signed** (since the genesis of the deployed
//! format, milestone M2): it embeds the Ed25519 [`PublicKey`] (32
//! bytes) of its signer and a 64-byte [`Signature`] over the canonical
//! signing payload defined by `scone-protocol`
//! (`SCONE-TX-SIG-V1` || canonical encoding of the transaction without
//! the signature — see `/docs/technical/transactions.md`).
//!
//! Since M8b every transaction also carries a [`NetworkId`] field
//! (`scone-testnet` / `scone-mainnet`): it is a **signed** field of the
//! payload, so a transaction built for one network never verifies on
//! another (network separation, see `crate::network`). The constructors
//! default it to the testnet id (the project is in development); the
//! chain layer enforces the match with its own network typedly
//! (`WrongNetwork`) at application time.
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

use crate::checkpoint::CheckpointData;
use crate::error::{Result, SconeError};
use crate::id::{DomainId, TldId};
use crate::name::{DomainName, TldName};
use crate::network::{NetworkId, TESTNET};
use crate::owner::{OwnerId, PublicKeyRef};

/// Opaque registration proof (the registration proof of work, M8b).
///
/// Pure types never interpret it; the state layer verifies it via
/// [`crate::pow`] when a proof is required (`RegisterTld`,
/// `RegisterDomain` under an open TLD).
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
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// Claimed domain, by canonical name (wire-visible).
    pub name: DomainName,
    /// Derived identity of `name` (recomputed, never trusted — see
    /// [`RegisterDomain::validate`]).
    pub domain_id: DomainId,
    pub owner: OwnerId,
    /// Ordering information (Unix timestamp now; chain position later).
    pub timestamp: u64,
    /// Registration proof of work (verified by the state layer, M8b).
    pub proof: Proof,
    /// Ed25519 public key of the signer (32 bytes, embedded so the
    /// signature can be verified offline).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl RegisterDomain {
    /// Builds a signed-shaped `RegisterDomain` for the **testnet**
    /// (development default), recomputing `owner` from `public_key`
    /// (the caller-supplied owner is never trusted — there is none).
    ///
    /// Use [`RegisterDomain::register_domain_on`] to target another
    /// network explicitly.
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
        Self::register_domain_on(
            TESTNET.network_id,
            name,
            timestamp,
            proof,
            public_key,
            signature,
        )
    }

    /// Builds a signed-shaped `RegisterDomain` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn register_domain_on(
        network: NetworkId,
        name: DomainName,
        timestamp: u64,
        proof: Proof,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
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
    /// The `proof` content is not interpreted here (the state layer
    /// verifies it via `crate::pow`).
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
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
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
    /// Builds a signed-shaped `UpdateDomain` for the **testnet**,
    /// recomputing `owner` from `public_key`.
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
        Self::update_domain_on(
            TESTNET.network_id,
            domain_id,
            sequence,
            record_hash,
            public_key,
            signature,
        )
    }

    /// Builds a signed-shaped `UpdateDomain` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn update_domain_on(
        network: NetworkId,
        domain_id: DomainId,
        sequence: u64,
        record_hash: RecordHash,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
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
/// Since M8b the transaction carries the **TLD name in clear**
/// ([`TldName`], like `RegisterDomain` carries the domain name): the
/// registration PoW challenge is `"SCONE-TLD-V1" || tld` and the chain
/// must be able to recompute it from the transaction alone. `tld_id`
/// stays the consensus identity and is re-derived from the carried
/// name on decode/validate.
///
/// Like every signed transaction: `owner` is ALWAYS recomputed from
/// the embedded `public_key` (never trusted); the `signature` must
/// cover the canonical signing payload of `scone-protocol`; `validate`
/// here only checks the pure invariants, not the signature itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterTld {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The claimed TLD, by canonical name (wire-visible, M8b).
    pub name: TldName,
    /// Derived identity of `name` (recomputed, never trusted — see
    /// [`RegisterTld::validate`]).
    pub tld_id: TldId,
    /// Recomputed owner identity (never trusted from input).
    pub owner: OwnerId,
    /// Ordering information (Unix timestamp now; chain position later).
    pub timestamp: u64,
    /// Registration proof of work (verified by the state layer, M8b).
    pub proof: Proof,
    /// Ed25519 public key of the signer (32 bytes, embedded so the
    /// signature can be verified offline).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl RegisterTld {
    /// Builds a signed-shaped `RegisterTld` for the **testnet**,
    /// deriving `tld_id` from `name` and recomputing `owner` from
    /// `public_key` (the caller-supplied owner is never trusted —
    /// there is none).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn register_tld_signed(
        name: TldName,
        timestamp: u64,
        proof: Proof,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::register_tld_on(
            TESTNET.network_id,
            name,
            timestamp,
            proof,
            public_key,
            signature,
        )
    }

    /// Builds a signed-shaped `RegisterTld` for `network`, deriving
    /// `tld_id` from the carried `name` (canonical constructor, M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn register_tld_on(
        network: NetworkId,
        name: TldName,
        timestamp: u64,
        proof: Proof,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            tld_id: TldId::from_tld(&name),
            name,
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
    /// - [`SconeError::InvalidOwner`] when `owner` is not the identity
    ///   derived from `public_key`;
    /// - [`SconeError::InvalidTld`] when `tld_id` is not the
    ///   derivation of the carried `name`.
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)?;
        if self.tld_id != TldId::from_tld(&self.name) {
            return Err(SconeError::InvalidTld(format!(
                "tld_id is not the derivation of the carried name {:?}",
                self.name.as_str()
            )));
        }
        Ok(())
    }
}

/// Transfers ownership of a registered TLD to another identity (M8a).
///
/// Signed by the **current** owner (the `owner`/`public_key` binding
/// rule applies as everywhere): the recipient only appears as
/// [`new_owner`](Self::new_owner), an opaque [`OwnerId`] that the
/// state layer matches against the new claimant of any subsequent
/// transaction on this TLD. Ordering between conflicting transfers is
/// resolved by chain order alone (no sequence number: a TLD has
/// exactly one owner at a time, the first applied transfer wins) —
/// see `/docs/technical/transactions.md`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransferTld {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The TLD being transferred.
    pub tld_id: TldId,
    /// Current owner (recomputed from `public_key`, never trusted).
    pub owner: OwnerId,
    /// The recipient identity (opaque: any `OwnerId` is syntactically
    /// valid; the state layer binds it to the keys that can spend it).
    pub new_owner: OwnerId,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl TransferTld {
    /// Builds a signed-shaped `TransferTld` for the **testnet**,
    /// recomputing `owner` from `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn transfer_tld_signed(
        tld_id: TldId,
        new_owner: OwnerId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::transfer_tld_on(TESTNET.network_id, tld_id, new_owner, public_key, signature)
    }

    /// Builds a signed-shaped `TransferTld` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn transfer_tld_on(
        network: NetworkId,
        tld_id: TldId,
        new_owner: OwnerId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            tld_id,
            owner: owner_of(&public_key),
            new_owner,
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidOwner`] when `owner` is not the
    /// identity derived from `public_key`.
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// Transfers ownership of a registered domain to a new owner
/// (M8c, symmetric of [`TransferTld`]).
///
/// Signed by the current owner. The recipient is any `OwnerId` (an
/// Ed25519-derived identity): the state layer binds it to the keys
/// that can spend it. Carries no timestamp: a transfer is one-shot
/// against the current state (domain exists, not expired, signer is
/// the owner — enforced at application time).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransferDomain {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The domain being transferred.
    pub domain_id: DomainId,
    /// Current owner (recomputed from `public_key`, never trusted).
    pub owner: OwnerId,
    /// The recipient identity.
    pub new_owner: OwnerId,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl TransferDomain {
    /// Builds a signed-shaped `TransferDomain` for the **testnet**,
    /// recomputing `owner` from `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn transfer_domain_signed(
        domain_id: DomainId,
        new_owner: OwnerId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::transfer_domain_on(
            TESTNET.network_id,
            domain_id,
            new_owner,
            public_key,
            signature,
        )
    }

    /// Builds a signed-shaped `TransferDomain` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn transfer_domain_on(
        network: NetworkId,
        domain_id: DomainId,
        new_owner: OwnerId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            domain_id,
            owner: owner_of(&public_key),
            new_owner,
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidOwner`] when `owner` is not the
    /// identity derived from `public_key`.
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// Relinquishes a registered TLD (M8a): the namespace becomes free
/// again and can be re-claimed with a fresh [`RegisterTld`].
///
/// Signed by the current owner. Deliberately carries no timestamp and
/// no sequence: a revoke is one-shot against the current state (TLD
/// exists and is owned by the signer — enforced at application time),
/// so chain order is the only ordering it needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RevokeTld {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The TLD being relinquished.
    pub tld_id: TldId,
    /// Current owner (recomputed from `public_key`, never trusted).
    pub owner: OwnerId,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl RevokeTld {
    /// Builds a signed-shaped `RevokeTld` for the **testnet**,
    /// recomputing `owner` from `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn revoke_tld_signed(tld_id: TldId, public_key: PublicKey, signature: Signature) -> Self {
        Self::revoke_tld_on(TESTNET.network_id, tld_id, public_key, signature)
    }

    /// Builds a signed-shaped `RevokeTld` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn revoke_tld_on(
        network: NetworkId,
        tld_id: TldId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            tld_id,
            owner: owner_of(&public_key),
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidOwner`] when `owner` is not the
    /// identity derived from `public_key`.
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// Opens or closes a TLD namespace for self-service domain
/// registration (M8a).
///
/// A **closed** TLD is assign-only: domains under it can be created
/// exclusively by the TLD owner with [`AssignDomain`]. An **open** TLD
/// lets anyone run the registration PoW and claim a free domain with
/// [`RegisterDomain`]. The flag is chain state (M8b): a `RegisterDomain`
/// under an open TLD requires the domain PoW; under a closed TLD it is
/// rejected outright (assign-only path).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SetTldOpen {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The TLD whose registration policy changes.
    pub tld_id: TldId,
    /// Current owner (recomputed from `public_key`, never trusted).
    pub owner: OwnerId,
    /// `true` = anyone may register free domains under this TLD
    /// (registration PoW still required); `false` = assign-only.
    pub open: bool,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl SetTldOpen {
    /// Builds a signed-shaped `SetTldOpen` for the **testnet**,
    /// recomputing `owner` from `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn set_tld_open_signed(
        tld_id: TldId,
        open: bool,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::set_tld_open_on(TESTNET.network_id, tld_id, open, public_key, signature)
    }

    /// Builds a signed-shaped `SetTldOpen` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn set_tld_open_on(
        network: NetworkId,
        tld_id: TldId,
        open: bool,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            tld_id,
            owner: owner_of(&public_key),
            open,
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidOwner`] when `owner` is not the
    /// identity derived from `public_key`.
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// Assigns a domain directly, signed by the **TLD owner** (M8a).
///
/// The assign-only path of a closed namespace: the signer must own
/// the TLD of `name` (checked at application time — pure types cannot
/// see the registry), and `assignee` becomes the first owner of the
/// domain. Mirrors [`RegisterDomain`]: the canonical name is carried
/// in clear and `domain_id` must be its derivation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssignDomain {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The assigned domain, by canonical name (wire-visible).
    pub name: DomainName,
    /// Derived identity of `name` (recomputed, never trusted).
    pub domain_id: DomainId,
    /// The TLD owner / signer (recomputed from `public_key`).
    pub owner: OwnerId,
    /// The identity that becomes the domain owner (opaque, like
    /// [`TransferTld::new_owner`]).
    pub assignee: OwnerId,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl AssignDomain {
    /// Builds a signed-shaped `AssignDomain` for the **testnet**,
    /// deriving `domain_id` from `name` and recomputing `owner` from
    /// `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn assign_domain_signed(
        name: DomainName,
        assignee: OwnerId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::assign_domain_on(TESTNET.network_id, name, assignee, public_key, signature)
    }

    /// Builds a signed-shaped `AssignDomain` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn assign_domain_on(
        network: NetworkId,
        name: DomainName,
        assignee: OwnerId,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            domain_id: DomainId::from_name(&name),
            owner: owner_of(&public_key),
            name,
            assignee,
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

/// Extends the registration of a domain until `valid_until` (M8a).
///
/// Signed by the current domain owner. `valid_until` is a Unix
/// timestamp in seconds; the pure layer only checks the owner/key
/// binding — whether it actually extends the current expiry (and by
/// at most one renewal term) is a state rule (M8b).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RenewDomain {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The domain whose registration is extended.
    pub domain_id: DomainId,
    /// Current owner (recomputed from `public_key`, never trusted).
    pub owner: OwnerId,
    /// New registration expiry (Unix seconds).
    pub valid_until: u64,
    /// Ed25519 public key of the signer (32 bytes).
    pub public_key: PublicKey,
    /// Ed25519 signature (64 bytes) over the canonical signing payload.
    pub signature: Signature,
}

impl RenewDomain {
    /// Builds a signed-shaped `RenewDomain` for the **testnet**,
    /// recomputing `owner` from `public_key`.
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn renew_domain_signed(
        domain_id: DomainId,
        valid_until: u64,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::renew_domain_on(
            TESTNET.network_id,
            domain_id,
            valid_until,
            public_key,
            signature,
        )
    }

    /// Builds a signed-shaped `RenewDomain` for `network` (M8b).
    ///
    /// See [`RegisterDomain::register_domain_signed`] for the signature contract.
    #[must_use]
    pub fn renew_domain_on(
        network: NetworkId,
        domain_id: DomainId,
        valid_until: u64,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            domain_id,
            owner: owner_of(&public_key),
            valid_until,
            public_key,
            signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidOwner`] when `owner` is not the
    /// identity derived from `public_key`.
    pub fn validate(&self) -> Result<()> {
        check_owner_binding(&self.owner, &self.public_key)
    }
}

/// Self-contained proof of checkpoint **equivocation** (M9, §9 of
/// the security model): the accused anchor signed TWO CONFLICTING
/// checkpoints at the SAME epoch, and anyone holding both signatures
/// can submit the proof on-chain (a "fraction fault proof" — one
/// honest witness suffices).
///
/// The cryptographic evidence is checked **without any chain
/// context** by [`SlashTx::verify_evidence`]: same epoch AND same
/// `prev_checkpoint_hash` (the conflicting context), distinct signing
/// hashes, and both signatures verifying under the SAME embedded
/// `offender` key. A signature over an abandoned branch remains a
/// valid proof forever.
///
/// The transaction itself is signed by an unrelated **reporter**
/// (standard transaction signature over the canonical signing
/// payload): they are only the messenger — the evidence speaks for
/// itself, and an eventual reporter incentive would be a state rule,
/// not a change here. The reporter pays nothing and gains nothing
/// today; their signature merely makes the tx a well-formed signed
/// transaction of the network (uniform validation) and gives the
/// anti-replay `TxId` a stable signer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SlashTx {
    /// Network this transaction is built for (M8b, signed field).
    pub network: NetworkId,
    /// The accused anchor's key (dedup/state target — redundant with
    /// the evidence, recomputed against it by `verify_evidence`).
    pub offender: PublicKey,
    /// First signed checkpoint of the conflicting pair.
    pub evidence_a: CheckpointData,
    /// Offender's signature over `evidence_a.signing_hash()`.
    pub sig_a: Signature,
    /// Second signed checkpoint of the conflicting pair.
    pub evidence_b: CheckpointData,
    /// Offender's signature over `evidence_b.signing_hash()`.
    pub sig_b: Signature,
    /// Reporter's Ed25519 public key (signs the tx itself).
    pub public_key: PublicKey,
    /// Reporter's signature over the canonical signing payload.
    pub signature: Signature,
}

impl SlashTx {
    /// Builds a `SlashTx` for the **testnet** from raw evidence (the
    /// reporter's signature must be produced over
    /// `scone_protocol::signing_payload` of the result).
    #[must_use]
    pub fn slash_signed(
        offender: PublicKey,
        evidence_a: CheckpointData,
        sig_a: Signature,
        evidence_b: CheckpointData,
        sig_b: Signature,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self::slash_on(
            TESTNET.network_id,
            offender,
            evidence_a,
            sig_a,
            evidence_b,
            sig_b,
            public_key,
            signature,
        )
    }

    /// Builds a `SlashTx` for `network` (see
    /// [`SlashTx::slash_signed`]).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn slash_on(
        network: NetworkId,
        offender: PublicKey,
        evidence_a: CheckpointData,
        sig_a: Signature,
        evidence_b: CheckpointData,
        sig_b: Signature,
        public_key: PublicKey,
        signature: Signature,
    ) -> Self {
        Self {
            network,
            offender,
            evidence_a,
            sig_a,
            evidence_b,
            sig_b,
            public_key,
            signature,
        }
    }

    /// Verifies the **cryptographic** evidence, with no chain state:
    ///
    /// - both checkpoints are at the SAME epoch AND chain the SAME
    ///   `prev_checkpoint_hash` (the conflicting context — the height
    ///   may differ: two checkpoints chaining the same parent at the
    ///   same epoch are contradictory regardless);
    /// - their signing hashes are DISTINCT (signing the same
    ///   checkpoint twice is not an equivocation);
    /// - `sig_a` / `sig_b` verify under the SAME `offender` key over
    ///   the respective signing hashes (`verify_strict`).
    #[must_use]
    pub fn verify_evidence(&self) -> bool {
        let (a, b) = (&self.evidence_a, &self.evidence_b);
        if a.epoch != b.epoch || a.prev_checkpoint_hash != b.prev_checkpoint_hash {
            return false; // different contexts: not an equivocation
        }
        let msg_a = a.signing_hash();
        let msg_b = b.signing_hash();
        if msg_a == msg_b {
            return false; // identical checkpoints: no contradiction
        }
        self.offender.verify(&msg_a, &self.sig_a) && self.offender.verify(&msg_b, &self.sig_b)
    }

    /// Checks protocol invariants: the reporter's key must be on the
    /// curve (decode-checked on the wire) and the evidence must be
    /// cryptographically self-consistent (the proof is the payload —
    /// a structurally invalid proof is an invalid transaction, not a
    /// state failure).
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidCheckpoint`] when the evidence
    /// does not verify (different epochs, different parents, same
    /// checkpoint twice, or a signature that fails under `offender`).
    pub fn validate(&self) -> Result<()> {
        if !self.verify_evidence() {
            return Err(SconeError::InvalidCheckpoint(
                "slash evidence is not a valid equivocation proof".into(),
            ));
        }
        Ok(())
    }
}

/// A signed blockchain transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::large_enum_variant)]
pub enum Transaction {
    /// See [`RegisterDomain`].
    RegisterDomain(RegisterDomain),
    /// See [`UpdateDomain`].
    UpdateDomain(UpdateDomain),
    /// See [`RegisterTld`] (TLD registry, M7).
    RegisterTld(RegisterTld),
    /// See [`TransferTld`] (TLD registry, M8a).
    TransferTld(TransferTld),
    /// See [`RevokeTld`] (TLD registry, M8a).
    RevokeTld(RevokeTld),
    /// See [`SetTldOpen`] (TLD registry, M8a).
    SetTldOpen(SetTldOpen),
    /// See [`AssignDomain`] (TLD registry, M8a).
    AssignDomain(AssignDomain),
    /// See [`RenewDomain`] (domain registry, M8a).
    RenewDomain(RenewDomain),
    /// See [`TransferDomain`] (domain registry, M8c).
    TransferDomain(TransferDomain),
    /// See [`SlashTx`] (checkpoint equivocation proof, M9).
    Slash(SlashTx),
}

impl Transaction {
    /// The network this transaction is built for (M8b).
    #[must_use]
    pub fn network(&self) -> NetworkId {
        match self {
            Self::RegisterDomain(tx) => tx.network,
            Self::UpdateDomain(tx) => tx.network,
            Self::RegisterTld(tx) => tx.network,
            Self::TransferTld(tx) => tx.network,
            Self::RevokeTld(tx) => tx.network,
            Self::SetTldOpen(tx) => tx.network,
            Self::AssignDomain(tx) => tx.network,
            Self::RenewDomain(tx) => tx.network,
            Self::TransferDomain(tx) => tx.network,
            Self::Slash(tx) => tx.network,
        }
    }

    /// The declared owner (always re-derived from
    /// [`Transaction::public_key`] by [`Transaction::validate`]).
    pub fn owner(&self) -> OwnerId {
        match self {
            Self::RegisterDomain(tx) => tx.owner,
            Self::UpdateDomain(tx) => tx.owner,
            Self::RegisterTld(tx) => tx.owner,
            Self::TransferTld(tx) => tx.owner,
            Self::RevokeTld(tx) => tx.owner,
            Self::SetTldOpen(tx) => tx.owner,
            Self::AssignDomain(tx) => tx.owner,
            Self::RenewDomain(tx) => tx.owner,
            Self::TransferDomain(tx) => tx.owner,
            // M9: the reporter is NOT the (only) owner of the tx — the
            // accused is. Expose the reporter's identity: it is the
            // derivation of the embedded key, like every owner.
            Self::Slash(tx) => owner_of(&tx.public_key),
        }
    }

    /// The embedded signer public key.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::RegisterDomain(tx) => &tx.public_key,
            Self::UpdateDomain(tx) => &tx.public_key,
            Self::RegisterTld(tx) => &tx.public_key,
            Self::TransferTld(tx) => &tx.public_key,
            Self::RevokeTld(tx) => &tx.public_key,
            Self::SetTldOpen(tx) => &tx.public_key,
            Self::AssignDomain(tx) => &tx.public_key,
            Self::RenewDomain(tx) => &tx.public_key,
            Self::TransferDomain(tx) => &tx.public_key,
            Self::Slash(tx) => &tx.public_key,
        }
    }

    /// The embedded signature.
    pub fn signature(&self) -> &Signature {
        match self {
            Self::RegisterDomain(tx) => &tx.signature,
            Self::UpdateDomain(tx) => &tx.signature,
            Self::RegisterTld(tx) => &tx.signature,
            Self::TransferTld(tx) => &tx.signature,
            Self::RevokeTld(tx) => &tx.signature,
            Self::SetTldOpen(tx) => &tx.signature,
            Self::AssignDomain(tx) => &tx.signature,
            Self::RenewDomain(tx) => &tx.signature,
            Self::TransferDomain(tx) => &tx.signature,
            Self::Slash(tx) => &tx.signature,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// - [`SconeError::InvalidSequence`] for an `UpdateDomain` with a zero
    ///   sequence;
    /// - [`SconeError::InvalidDomain`] for a `RegisterDomain` whose
    ///   `domain_id` does not match its carried name (same for
    ///   `AssignDomain`, and `InvalidTld` for a `RegisterTld` whose
    ///   `tld_id` does not match its carried name);
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
            Self::TransferTld(tx) => tx.validate(),
            Self::RevokeTld(tx) => tx.validate(),
            Self::SetTldOpen(tx) => tx.validate(),
            Self::AssignDomain(tx) => tx.validate(),
            Self::RenewDomain(tx) => tx.validate(),
            Self::TransferDomain(tx) => tx.validate(),
            Self::Slash(tx) => tx.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MAINNET;
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
        assert_eq!(reg.network(), TESTNET.network_id);
        assert_eq!(upd.network(), TESTNET.network_id);
    }

    // --- RegisterTld (M7a) ---

    fn tld_name() -> TldName {
        TldName::new("uip").unwrap()
    }

    fn tld_id() -> TldId {
        TldId::from_tld(&tld_name())
    }

    fn register_tld() -> RegisterTld {
        RegisterTld::register_tld_on(
            TESTNET.network_id,
            tld_name(),
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
        let tx = RegisterTld::register_tld_on(
            TESTNET.network_id,
            tld_name(),
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
        let mut tx = RegisterTld::register_tld_on(
            TESTNET.network_id,
            tld_name(),
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
        // …derived from the carried name…
        assert_eq!(tx.tld_id, TldId::from_tld(&tx.name));
        // …and disjoint from any domain derivation.
        assert_ne!(tx.tld_id.as_bytes(), domain_id().as_bytes());
    }

    #[test]
    fn register_tld_name_id_mismatch_is_invalid() {
        let mut tx = register_tld();
        tx.tld_id = TldId::from_tld(&TldName::new("com").unwrap());
        assert!(matches!(tx.validate(), Err(SconeError::InvalidTld(_))));
    }

    // --- M8a: TransferTld / RevokeTld / SetTldOpen / AssignDomain
    // / RenewDomain ---

    fn assignee() -> OwnerId {
        owner_of(&key(2).public_key())
    }

    #[test]
    fn m8a_constructors_recompute_owner_and_derive_ids() {
        let sk = key(5);
        let transfer = TransferTld::transfer_tld_on(
            TESTNET.network_id,
            tld_id(),
            assignee(),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(transfer.owner, owner_of(&sk.public_key()));
        assert_eq!(transfer.new_owner, assignee());
        assert!(transfer.validate().is_ok());

        let revoke = RevokeTld::revoke_tld_on(
            TESTNET.network_id,
            tld_id(),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(revoke.owner, owner_of(&sk.public_key()));
        assert!(revoke.validate().is_ok());

        let set_open = SetTldOpen::set_tld_open_on(
            TESTNET.network_id,
            tld_id(),
            true,
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(set_open.owner, owner_of(&sk.public_key()));
        assert!(set_open.validate().is_ok());

        let assign = AssignDomain::assign_domain_on(
            TESTNET.network_id,
            name(),
            assignee(),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(assign.owner, owner_of(&sk.public_key()));
        assert_eq!(assign.domain_id, domain_id());
        assert!(assign.validate().is_ok());

        let renew = RenewDomain::renew_domain_on(
            TESTNET.network_id,
            domain_id(),
            1_800_000_000,
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(renew.owner, owner_of(&sk.public_key()));
        assert!(renew.validate().is_ok());
    }

    #[test]
    fn m8a_owner_key_mismatch_is_invalid_everywhere() {
        let sk_a = key(1);
        let sk_b = key(2);
        let forged = owner_of(&sk_b.public_key());

        let mut transfer = TransferTld::transfer_tld_on(
            TESTNET.network_id,
            tld_id(),
            assignee(),
            sk_a.public_key(),
            placeholder_signature(),
        );
        transfer.owner = forged;
        assert!(matches!(
            transfer.validate(),
            Err(SconeError::InvalidOwner(_))
        ));

        let mut revoke = RevokeTld::revoke_tld_on(
            TESTNET.network_id,
            tld_id(),
            sk_a.public_key(),
            placeholder_signature(),
        );
        revoke.owner = forged;
        assert!(matches!(
            revoke.validate(),
            Err(SconeError::InvalidOwner(_))
        ));

        let mut set_open = SetTldOpen::set_tld_open_on(
            TESTNET.network_id,
            tld_id(),
            false,
            sk_a.public_key(),
            placeholder_signature(),
        );
        set_open.owner = forged;
        assert!(matches!(
            set_open.validate(),
            Err(SconeError::InvalidOwner(_))
        ));

        let mut assign = AssignDomain::assign_domain_on(
            TESTNET.network_id,
            name(),
            assignee(),
            sk_a.public_key(),
            placeholder_signature(),
        );
        assign.owner = forged;
        assert!(matches!(
            assign.validate(),
            Err(SconeError::InvalidOwner(_))
        ));

        let mut renew = RenewDomain::renew_domain_on(
            TESTNET.network_id,
            domain_id(),
            1,
            sk_a.public_key(),
            placeholder_signature(),
        );
        renew.owner = forged;
        assert!(matches!(renew.validate(), Err(SconeError::InvalidOwner(_))));
    }

    #[test]
    fn assign_domain_name_id_mismatch_is_invalid() {
        let mut assign = AssignDomain::assign_domain_on(
            TESTNET.network_id,
            name(),
            assignee(),
            key(1).public_key(),
            placeholder_signature(),
        );
        assign.domain_id = DomainId::from_name(&DomainName::new("other.uip").unwrap());
        assert!(matches!(
            assign.validate(),
            Err(SconeError::InvalidDomain(_))
        ));
    }

    #[test]
    fn m8a_transaction_accessors_cover_the_new_variants() {
        let renew = Transaction::RenewDomain(RenewDomain::renew_domain_on(
            TESTNET.network_id,
            domain_id(),
            1,
            key(3).public_key(),
            placeholder_signature(),
        ));
        assert_eq!(renew.owner(), owner_of(&key(3).public_key()));
        assert_eq!(renew.public_key(), &key(3).public_key());
        assert_eq!(renew.signature(), &placeholder_signature());
        assert!(renew.validate().is_ok());

        let transfer = Transaction::TransferTld(TransferTld::transfer_tld_on(
            TESTNET.network_id,
            tld_id(),
            assignee(),
            key(3).public_key(),
            placeholder_signature(),
        ));
        assert_eq!(transfer.owner(), renew.owner());
        assert!(transfer.validate().is_ok());
    }

    // --- M8b: network field ---

    #[test]
    fn on_network_constructors_set_the_network() {
        let sk = key(4);
        let reg = RegisterDomain::register_domain_on(
            MAINNET.network_id,
            name(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(reg.network, MAINNET.network_id);
        assert_eq!(
            Transaction::RegisterDomain(reg).network(),
            MAINNET.network_id
        );

        let tld = RegisterTld::register_tld_on(
            MAINNET.network_id,
            tld_name(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(tld.network, MAINNET.network_id);
        assert_eq!(tld.tld_id, tld_id());
        assert!(tld.validate().is_ok());

        let renew = RenewDomain::renew_domain_on(
            MAINNET.network_id,
            domain_id(),
            1,
            sk.public_key(),
            placeholder_signature(),
        );
        assert_eq!(
            Transaction::RenewDomain(renew).network(),
            MAINNET.network_id
        );
    }

    #[test]
    fn legacy_default_constructors_target_testnet() {
        // The `*_signed` shapes keep their M7 signatures and default
        // to the testnet: development stays zero-friction, the chain
        // layer is the one that enforces the real network.
        let reg = register();
        assert_eq!(reg.network, TESTNET.network_id);
        let renew = RenewDomain::renew_domain_signed(
            domain_id(),
            1,
            key(1).public_key(),
            placeholder_signature(),
        );
        assert_eq!(renew.network, TESTNET.network_id);
    }

    // --- M9: SlashTx (equivocation evidence) ---

    use crate::checkpoint::CheckpointData;

    fn evidence(epoch: u64, height: u64, root: u8) -> CheckpointData {
        CheckpointData {
            epoch,
            height,
            block_hash: [root; 32],
            prev_checkpoint_hash: [0x42; 32],
            state_root: [root; 32],
            recovery: 0,
        }
    }

    /// A valid SlashTx: key 1 double-signed two conflicting
    /// checkpoints at epoch 7 (same prev, distinct roots), reporter
    /// key 9.
    fn valid_slash() -> SlashTx {
        let offender = key(1);
        let a = evidence(7, 10, 1);
        let b = evidence(7, 11, 2);
        let sig_a = offender.sign(&a.signing_hash());
        let sig_b = offender.sign(&b.signing_hash());
        SlashTx::slash_signed(
            offender.public_key(),
            a,
            sig_a,
            b,
            sig_b,
            key(9).public_key(),
            placeholder_signature(),
        )
    }

    #[test]
    fn slash_valid_evidence_verifies() {
        let tx = valid_slash();
        assert!(tx.verify_evidence());
        assert!(tx.validate().is_ok());
        assert!(Transaction::Slash(tx).validate().is_ok());
    }

    #[test]
    fn slash_same_checkpoint_twice_is_not_an_equivocation() {
        let offender = key(1);
        let a = evidence(7, 10, 1);
        let sig = offender.sign(&a.signing_hash());
        let tx = SlashTx::slash_signed(
            offender.public_key(),
            a.clone(),
            sig,
            a,
            sig,
            key(9).public_key(),
            placeholder_signature(),
        );
        assert!(!tx.verify_evidence());
        assert!(matches!(
            tx.validate(),
            Err(SconeError::InvalidCheckpoint(_))
        ));
    }

    #[test]
    fn slash_different_epoch_is_not_an_equivocation() {
        let offender = key(1);
        let a = evidence(7, 10, 1);
        let b = evidence(8, 11, 2);
        let tx = SlashTx::slash_signed(
            offender.public_key(),
            a.clone(),
            offender.sign(&a.signing_hash()),
            b.clone(),
            offender.sign(&b.signing_hash()),
            key(9).public_key(),
            placeholder_signature(),
        );
        assert!(!tx.verify_evidence());
    }

    #[test]
    fn slash_different_parent_is_not_an_equivocation() {
        let offender = key(1);
        let mut a = evidence(7, 10, 1);
        let mut b = evidence(7, 11, 2);
        b.prev_checkpoint_hash = [0x99; 32];
        a.prev_checkpoint_hash = [0x42; 32];
        let tx = SlashTx::slash_signed(
            offender.public_key(),
            a.clone(),
            offender.sign(&a.signing_hash()),
            b.clone(),
            offender.sign(&b.signing_hash()),
            key(9).public_key(),
            placeholder_signature(),
        );
        assert!(!tx.verify_evidence());
    }

    #[test]
    fn slash_forged_signature_is_rejected() {
        // A signature produced by ANOTHER key does not verify under
        // the offender.
        let mut tx = valid_slash();
        tx.sig_b = key(2).sign(&tx.evidence_b.signing_hash());
        assert!(!tx.verify_evidence());
        // Tampered bytes as well.
        let mut tx = valid_slash();
        let mut raw = tx.sig_a.to_bytes();
        raw[0] ^= 0x01;
        tx.sig_a = Signature::from_bytes(raw);
        assert!(!tx.verify_evidence());
    }

    #[test]
    fn slash_wrong_offender_key_is_rejected() {
        // Evidence signed by key 1, but key 2 is accused.
        let mut tx = valid_slash();
        tx.offender = key(2).public_key();
        assert!(!tx.verify_evidence());
    }

    #[test]
    fn slash_different_heights_same_context_still_equivocation() {
        // Two checkpoints chaining the SAME parent at the SAME epoch
        // conflict even at different heights (documented rule).
        let tx = valid_slash();
        assert_ne!(tx.evidence_a.height, tx.evidence_b.height);
        assert!(tx.verify_evidence());
    }

    #[test]
    fn slash_accessors() {
        let tx = valid_slash();
        let wrapped = Transaction::Slash(tx);
        assert_eq!(wrapped.network(), TESTNET.network_id);
        assert_eq!(wrapped.owner(), owner_of(&key(9).public_key()));
        assert_eq!(wrapped.public_key(), &key(9).public_key());
        assert_eq!(wrapped.signature(), &placeholder_signature());
    }
}
