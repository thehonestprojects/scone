//! Wire encoding of blockchain transactions (signed format).
//!
//! ```text
//! Transaction = disc u8 || version u8 (0x01) || payload
//!   0x21 RegisterDomain
//!   0x52 UpdateDomain
//!   0x93 RegisterTld
//!   0x47 TransferTld      (M8a)
//!   0x6B RevokeTld        (M8a)
//!   0xB8 SetTldOpen       (M8a)
//!   0xD4 AssignDomain     (M8a)
//!   0x3C RenewDomain      (M8a)
//! ```
//!
//! The `version` byte after the discriminator must be exactly
//! `0x01`: any other value is rejected with
//! [`ProtocolError::UnsupportedVersion`] (generic invalid-version
//! rule).
//!
//! Every transaction embeds the signer's Ed25519 public key (32 raw
//! bytes) and signature (exactly 64 raw bytes — no length prefix, no
//! headroom: any other size is a hard decode error).
//!
//! The signed payload is [`signing_payload`]: the `SCONE-TX-SIG-V1`
//! prefix followed by the canonical encoding of the transaction
//! **without** the signature. See `/docs/technical/transactions.md` (normative).

use scone_core::{
    AssignDomain, DomainId, DomainName, OwnerId, Proof, RecordHash, RegisterDomain, RegisterTld,
    RenewDomain, RevokeTld, SetTldOpen, Transaction, TransferTld, UpdateDomain,
};
use scone_crypto::{PublicKey, Signature};

use crate::codec::{self, Decode, Encode};
use crate::error::{ProtocolError, Result};
use crate::varint;

/// Transaction wire discriminants.
///
/// Allocation rule (normative, see `/docs/technical/transactions.md`):
/// each discriminant is a **fixed, arbitrary, opaque value** — chosen
/// distinct on purpose so the wire never suggests a logical order
/// between types. `0x00` is never a valid type (typical corruption
/// byte). Future types take any unused value, documented once and for
/// all in the normative table.
pub mod tx_type {
    /// Claims ownership of a domain.
    pub const REGISTER_DOMAIN: u8 = 0x21;
    /// Publishes a new version of a domain's DNS data.
    pub const UPDATE_DOMAIN: u8 = 0x52;
    /// Claims ownership of a top-level domain (M7b).
    pub const REGISTER_TLD: u8 = 0x93;
    /// Transfers a TLD to a new owner (M8a).
    pub const TRANSFER_TLD: u8 = 0x47;
    /// Relinquishes a TLD (M8a).
    pub const REVOKE_TLD: u8 = 0x6B;
    /// Opens/closes a TLD for self-service registration (M8a).
    pub const SET_TLD_OPEN: u8 = 0xB8;
    /// Assigns a domain directly (TLD owner, M8a).
    pub const ASSIGN_DOMAIN: u8 = 0xD4;
    /// Extends a domain registration (M8a).
    pub const RENEW_DOMAIN: u8 = 0x3C;
}

/// Version byte of the signed transaction format.
pub const TX_FORMAT_VERSION: u8 = 0x01;

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

// RegisterDomain = network(str ≤ 16) || name(str ≤ 253) || domain_id[32]
//        || owner[32] || timestamp.v || proof || public_key[32]
//        || signature[64]
//
// The canonical name is carried in clear (M7b): the chain is
// self-describing and decode re-checks domain_id == from_name(name).
// The network id is a signed field (M8b).

impl Encode for RegisterDomain {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        // Binding owner/pk and name/id vérifié aussi à l'encodage
        // (symétrie avec UpdateDomain, docs/transactions.md — doc normative).
        self.validate()?;
        self.network.encode(out)?;
        self.name.encode(out)?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.timestamp, out);
        self.proof.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for RegisterDomain {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let register = Self {
            network: scone_core::NetworkId::decode(input)?,
            name: DomainName::decode(input)?,
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

// RegisterTld (M8b) = network(str ≤ 16) || tld(str ≤ 63)
//        || tld_id[32] || owner[32] || timestamp.v || proof
//        || public_key[32] || signature[64]
//
// The TLD name is carried in clear (M8b, mirroring RegisterDomain):
// the registration PoW challenge is derived from the name and decode
// re-checks tld_id == from_tld(name).

impl Encode for RegisterTld {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.name.encode(out)?;
        self.tld_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.timestamp, out);
        self.proof.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for RegisterTld {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let register_tld = Self {
            network: scone_core::NetworkId::decode(input)?,
            name: scone_core::TldName::decode(input)?,
            tld_id: scone_core::TldId::decode(input)?,
            owner: OwnerId::decode(input)?,
            timestamp: u64::decode(input)?,
            proof: Proof::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        register_tld.validate().map_err(ProtocolError::Validation)?;
        Ok(register_tld)
    }
}

// UpdateDomain = network(str ≤ 16) || domain_id[32] || owner[32]
//        || sequence.v || record_hash[32] || public_key[32]
//        || signature[64]

impl Encode for UpdateDomain {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.sequence, out);
        self.record_hash.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for UpdateDomain {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let update = Self {
            network: scone_core::NetworkId::decode(input)?,
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

// bool = one raw byte, strictly 0x00 or 0x01 (canonical form: any
// other value is rejected on decode instead of being coerced).

impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.push(u8::from(*self));
        Ok(())
    }
}

impl Decode for bool {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        match codec::take_u8(input)? {
            0x00 => Ok(false),
            0x01 => Ok(true),
            _ => Err(ProtocolError::NonCanonical(
                "boolean must be exactly 0x00 or 0x01",
            )),
        }
    }
}

// TransferTld (M8a) = tld_id[32] || owner[32] || new_owner[32]
//        || public_key[32] || signature[64]

impl Encode for TransferTld {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.tld_id.encode(out)?;
        self.owner.encode(out)?;
        self.new_owner.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for TransferTld {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let transfer = Self {
            network: scone_core::NetworkId::decode(input)?,
            tld_id: scone_core::TldId::decode(input)?,
            owner: OwnerId::decode(input)?,
            new_owner: OwnerId::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        transfer.validate().map_err(ProtocolError::Validation)?;
        Ok(transfer)
    }
}

// RevokeTld (M8a) = tld_id[32] || owner[32] || public_key[32]
//        || signature[64]

impl Encode for RevokeTld {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.tld_id.encode(out)?;
        self.owner.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for RevokeTld {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let revoke = Self {
            network: scone_core::NetworkId::decode(input)?,
            tld_id: scone_core::TldId::decode(input)?,
            owner: OwnerId::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        revoke.validate().map_err(ProtocolError::Validation)?;
        Ok(revoke)
    }
}

// SetTldOpen (M8a) = tld_id[32] || owner[32] || open u8 (0x00|0x01)
//        || public_key[32] || signature[64]

impl Encode for SetTldOpen {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.tld_id.encode(out)?;
        self.owner.encode(out)?;
        self.open.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for SetTldOpen {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let set_open = Self {
            network: scone_core::NetworkId::decode(input)?,
            tld_id: scone_core::TldId::decode(input)?,
            owner: OwnerId::decode(input)?,
            open: bool::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        set_open.validate().map_err(ProtocolError::Validation)?;
        Ok(set_open)
    }
}

// AssignDomain (M8a) = name(str ≤ 253) || domain_id[32] || owner[32]
//        || assignee[32] || public_key[32] || signature[64]
//
// Mirrors RegisterDomain: the canonical name is carried in clear and
// decode re-checks domain_id == from_name(name).

impl Encode for AssignDomain {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.name.encode(out)?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        self.assignee.encode(out)?;
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for AssignDomain {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let assign = Self {
            network: scone_core::NetworkId::decode(input)?,
            name: DomainName::decode(input)?,
            domain_id: DomainId::decode(input)?,
            owner: OwnerId::decode(input)?,
            assignee: OwnerId::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        assign.validate().map_err(ProtocolError::Validation)?;
        Ok(assign)
    }
}

// RenewDomain (M8a) = domain_id[32] || owner[32] || valid_until.v
//        || public_key[32] || signature[64]

impl Encode for RenewDomain {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        self.network.encode(out)?;
        self.domain_id.encode(out)?;
        self.owner.encode(out)?;
        varint::put_u64(self.valid_until, out);
        self.public_key.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for RenewDomain {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let renew = Self {
            network: scone_core::NetworkId::decode(input)?,
            domain_id: DomainId::decode(input)?,
            owner: OwnerId::decode(input)?,
            valid_until: u64::decode(input)?,
            public_key: PublicKey::decode(input)?,
            signature: Signature::decode(input)?,
        };
        renew.validate().map_err(ProtocolError::Validation)?;
        Ok(renew)
    }
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::RegisterDomain(tx) => {
                out.push(tx_type::REGISTER_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::UpdateDomain(tx) => {
                out.push(tx_type::UPDATE_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::RegisterTld(tx) => {
                out.push(tx_type::REGISTER_TLD);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::TransferTld(tx) => {
                out.push(tx_type::TRANSFER_TLD);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::RevokeTld(tx) => {
                out.push(tx_type::REVOKE_TLD);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::SetTldOpen(tx) => {
                out.push(tx_type::SET_TLD_OPEN);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::AssignDomain(tx) => {
                out.push(tx_type::ASSIGN_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                tx.encode(out)
            }
            Self::RenewDomain(tx) => {
                out.push(tx_type::RENEW_DOMAIN);
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
            return Err(ProtocolError::UnsupportedVersion(u64::from(version)));
        }
        Ok(match disc {
            tx_type::REGISTER_DOMAIN => Self::RegisterDomain(RegisterDomain::decode(input)?),
            tx_type::UPDATE_DOMAIN => Self::UpdateDomain(UpdateDomain::decode(input)?),
            tx_type::REGISTER_TLD => Self::RegisterTld(RegisterTld::decode(input)?),
            tx_type::TRANSFER_TLD => Self::TransferTld(TransferTld::decode(input)?),
            tx_type::REVOKE_TLD => Self::RevokeTld(RevokeTld::decode(input)?),
            tx_type::SET_TLD_OPEN => Self::SetTldOpen(SetTldOpen::decode(input)?),
            tx_type::ASSIGN_DOMAIN => Self::AssignDomain(AssignDomain::decode(input)?),
            tx_type::RENEW_DOMAIN => Self::RenewDomain(RenewDomain::decode(input)?),
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
    /// See [`scone_core::RegisterDomain`].
    RegisterDomain {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// Claimed domain, canonical name.
        name: DomainName,
        /// Derived identity of `name`.
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
    /// See [`scone_core::UpdateDomain`].
    UpdateDomain {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
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
    /// See [`scone_core::RegisterTld`].
    RegisterTld {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// Claimed TLD, canonical name (M8b).
        name: scone_core::TldName,
        /// Claimed TLD (namespace id).
        tld_id: scone_core::TldId,
        /// Derived owner identity.
        owner: OwnerId,
        /// Ordering information.
        timestamp: u64,
        /// Registration proof (opaque).
        proof: Proof,
        /// Signer public key.
        public_key: PublicKey,
    },
    /// See [`scone_core::TransferTld`] (M8a).
    TransferTld {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// Transferred TLD.
        tld_id: scone_core::TldId,
        /// Derived owner identity (current owner / signer).
        owner: OwnerId,
        /// Recipient identity.
        new_owner: OwnerId,
        /// Signer public key.
        public_key: PublicKey,
    },
    /// See [`scone_core::RevokeTld`] (M8a).
    RevokeTld {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// Relinquished TLD.
        tld_id: scone_core::TldId,
        /// Derived owner identity.
        owner: OwnerId,
        /// Signer public key.
        public_key: PublicKey,
    },
    /// See [`scone_core::SetTldOpen`] (M8a).
    SetTldOpen {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// TLD whose registration policy changes.
        tld_id: scone_core::TldId,
        /// Derived owner identity.
        owner: OwnerId,
        /// `true` = open for self-service registration.
        open: bool,
        /// Signer public key.
        public_key: PublicKey,
    },
    /// See [`scone_core::AssignDomain`] (M8a).
    AssignDomain {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// Assigned domain, canonical name.
        name: DomainName,
        /// Derived identity of `name`.
        domain_id: DomainId,
        /// Derived owner identity (TLD owner / signer).
        owner: OwnerId,
        /// Identity that becomes the domain owner.
        assignee: OwnerId,
        /// Signer public key.
        public_key: PublicKey,
    },
    /// See [`scone_core::RenewDomain`] (M8a).
    RenewDomain {
        /// Network this transaction is built for (M8b).
        network: scone_core::NetworkId,
        /// Domain whose registration is extended.
        domain_id: DomainId,
        /// Derived owner identity.
        owner: OwnerId,
        /// New registration expiry (Unix seconds).
        valid_until: u64,
        /// Signer public key.
        public_key: PublicKey,
    },
}

impl From<&Transaction> for UnsignedTransaction {
    fn from(tx: &Transaction) -> Self {
        match tx {
            Transaction::RegisterDomain(tx) => Self::RegisterDomain {
                network: tx.network,
                name: tx.name.clone(),
                domain_id: tx.domain_id,
                owner: tx.owner,
                timestamp: tx.timestamp,
                proof: tx.proof.clone(),
                public_key: tx.public_key,
            },
            Transaction::UpdateDomain(tx) => Self::UpdateDomain {
                network: tx.network,
                domain_id: tx.domain_id,
                owner: tx.owner,
                sequence: tx.sequence,
                record_hash: tx.record_hash,
                public_key: tx.public_key,
            },
            Transaction::RegisterTld(tx) => Self::RegisterTld {
                network: tx.network,
                name: tx.name.clone(),
                tld_id: tx.tld_id,
                owner: tx.owner,
                timestamp: tx.timestamp,
                proof: tx.proof.clone(),
                public_key: tx.public_key,
            },
            Transaction::TransferTld(tx) => Self::TransferTld {
                network: tx.network,
                tld_id: tx.tld_id,
                owner: tx.owner,
                new_owner: tx.new_owner,
                public_key: tx.public_key,
            },
            Transaction::RevokeTld(tx) => Self::RevokeTld {
                network: tx.network,
                tld_id: tx.tld_id,
                owner: tx.owner,
                public_key: tx.public_key,
            },
            Transaction::SetTldOpen(tx) => Self::SetTldOpen {
                network: tx.network,
                tld_id: tx.tld_id,
                owner: tx.owner,
                open: tx.open,
                public_key: tx.public_key,
            },
            Transaction::AssignDomain(tx) => Self::AssignDomain {
                network: tx.network,
                name: tx.name.clone(),
                domain_id: tx.domain_id,
                owner: tx.owner,
                assignee: tx.assignee,
                public_key: tx.public_key,
            },
            Transaction::RenewDomain(tx) => Self::RenewDomain {
                network: tx.network,
                domain_id: tx.domain_id,
                owner: tx.owner,
                valid_until: tx.valid_until,
                public_key: tx.public_key,
            },
        }
    }
}

impl Encode for UnsignedTransaction {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::RegisterDomain {
                network,
                name,
                domain_id,
                owner,
                timestamp,
                proof,
                public_key,
            } => {
                out.push(tx_type::REGISTER_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                name.encode(out)?;
                domain_id.encode(out)?;
                owner.encode(out)?;
                varint::put_u64(*timestamp, out);
                proof.encode(out)?;
                public_key.encode(out)
            }
            Self::UpdateDomain {
                network,
                domain_id,
                owner,
                sequence,
                record_hash,
                public_key,
            } => {
                out.push(tx_type::UPDATE_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                domain_id.encode(out)?;
                owner.encode(out)?;
                varint::put_u64(*sequence, out);
                record_hash.encode(out)?;
                public_key.encode(out)
            }
            Self::RegisterTld {
                network,
                name,
                tld_id,
                owner,
                timestamp,
                proof,
                public_key,
            } => {
                out.push(tx_type::REGISTER_TLD);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                name.encode(out)?;
                tld_id.encode(out)?;
                owner.encode(out)?;
                varint::put_u64(*timestamp, out);
                proof.encode(out)?;
                public_key.encode(out)
            }
            Self::TransferTld {
                network,
                tld_id,
                owner,
                new_owner,
                public_key,
            } => {
                out.push(tx_type::TRANSFER_TLD);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                tld_id.encode(out)?;
                owner.encode(out)?;
                new_owner.encode(out)?;
                public_key.encode(out)
            }
            Self::RevokeTld {
                network,
                tld_id,
                owner,
                public_key,
            } => {
                out.push(tx_type::REVOKE_TLD);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                tld_id.encode(out)?;
                owner.encode(out)?;
                public_key.encode(out)
            }
            Self::SetTldOpen {
                network,
                tld_id,
                owner,
                open,
                public_key,
            } => {
                out.push(tx_type::SET_TLD_OPEN);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                tld_id.encode(out)?;
                owner.encode(out)?;
                open.encode(out)?;
                public_key.encode(out)
            }
            Self::AssignDomain {
                network,
                name,
                domain_id,
                owner,
                assignee,
                public_key,
            } => {
                out.push(tx_type::ASSIGN_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                name.encode(out)?;
                domain_id.encode(out)?;
                owner.encode(out)?;
                assignee.encode(out)?;
                public_key.encode(out)
            }
            Self::RenewDomain {
                network,
                domain_id,
                owner,
                valid_until,
                public_key,
            } => {
                out.push(tx_type::RENEW_DOMAIN);
                out.push(TX_FORMAT_VERSION);
                network.encode(out)?;
                domain_id.encode(out)?;
                owner.encode(out)?;
                varint::put_u64(*valid_until, out);
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
            tx_type::REGISTER_DOMAIN => Self::RegisterDomain {
                network: scone_core::NetworkId::decode(input)?,
                name: DomainName::decode(input)?,
                domain_id: DomainId::decode(input)?,
                owner: OwnerId::decode(input)?,
                timestamp: u64::decode(input)?,
                proof: Proof::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::UPDATE_DOMAIN => Self::UpdateDomain {
                network: scone_core::NetworkId::decode(input)?,
                domain_id: DomainId::decode(input)?,
                owner: OwnerId::decode(input)?,
                sequence: u64::decode(input)?,
                record_hash: RecordHash::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::REGISTER_TLD => Self::RegisterTld {
                network: scone_core::NetworkId::decode(input)?,
                name: scone_core::TldName::decode(input)?,
                tld_id: scone_core::TldId::decode(input)?,
                owner: OwnerId::decode(input)?,
                timestamp: u64::decode(input)?,
                proof: Proof::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::TRANSFER_TLD => Self::TransferTld {
                network: scone_core::NetworkId::decode(input)?,
                tld_id: scone_core::TldId::decode(input)?,
                owner: OwnerId::decode(input)?,
                new_owner: OwnerId::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::REVOKE_TLD => Self::RevokeTld {
                network: scone_core::NetworkId::decode(input)?,
                tld_id: scone_core::TldId::decode(input)?,
                owner: OwnerId::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::SET_TLD_OPEN => Self::SetTldOpen {
                network: scone_core::NetworkId::decode(input)?,
                tld_id: scone_core::TldId::decode(input)?,
                owner: OwnerId::decode(input)?,
                open: bool::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::ASSIGN_DOMAIN => Self::AssignDomain {
                network: scone_core::NetworkId::decode(input)?,
                name: DomainName::decode(input)?,
                domain_id: DomainId::decode(input)?,
                owner: OwnerId::decode(input)?,
                assignee: OwnerId::decode(input)?,
                public_key: PublicKey::decode(input)?,
            },
            tx_type::RENEW_DOMAIN => Self::RenewDomain {
                network: scone_core::NetworkId::decode(input)?,
                domain_id: DomainId::decode(input)?,
                owner: OwnerId::decode(input)?,
                valid_until: u64::decode(input)?,
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
    use scone_core::{DomainName, TldId, TldName};
    use scone_crypto::SigningKey;

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn name() -> DomainName {
        DomainName::new("example.uip").unwrap()
    }

    fn tld_id() -> TldId {
        TldId::from_tld(&TldName::new("uip").unwrap())
    }

    fn tld_name() -> TldName {
        TldName::new("uip").unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn signed_register_domain() -> RegisterDomain {
        let sk = key(1);
        let unsigned = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            name(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        RegisterDomain::register_domain_signed(
            name(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    fn signed_update_domain() -> UpdateDomain {
        let sk = key(1);
        let unsigned = Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        UpdateDomain::update_domain_signed(
            domain_id(),
            1,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    fn signed_register_tld() -> RegisterTld {
        let sk = key(1);
        let unsigned = Transaction::RegisterTld(RegisterTld::register_tld_signed(
            tld_name(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        RegisterTld::register_tld_signed(
            tld_name(),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    fn signed_transfer_tld() -> TransferTld {
        let sk = key(5);
        let unsigned = Transaction::TransferTld(TransferTld::transfer_tld_signed(
            tld_id(),
            OwnerId::from_bytes([0xee; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        TransferTld::transfer_tld_signed(
            tld_id(),
            OwnerId::from_bytes([0xee; 32]),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    fn signed_revoke_tld() -> RevokeTld {
        let sk = key(6);
        let unsigned = Transaction::RevokeTld(RevokeTld::revoke_tld_signed(
            tld_id(),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        RevokeTld::revoke_tld_signed(tld_id(), sk.public_key(), sk.sign(&payload))
    }

    fn signed_set_tld_open() -> SetTldOpen {
        let sk = key(7);
        let unsigned = Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
            tld_id(),
            true,
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        SetTldOpen::set_tld_open_signed(tld_id(), true, sk.public_key(), sk.sign(&payload))
    }

    fn signed_assign_domain() -> AssignDomain {
        let sk = key(8);
        let unsigned = Transaction::AssignDomain(AssignDomain::assign_domain_signed(
            name(),
            OwnerId::from_bytes([0xdd; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        AssignDomain::assign_domain_signed(
            name(),
            OwnerId::from_bytes([0xdd; 32]),
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    fn signed_renew_domain() -> RenewDomain {
        let sk = key(9);
        let unsigned = Transaction::RenewDomain(RenewDomain::renew_domain_signed(
            domain_id(),
            1_800_000_000,
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        RenewDomain::renew_domain_signed(
            domain_id(),
            1_800_000_000,
            sk.public_key(),
            sk.sign(&payload),
        )
    }

    #[test]
    fn register_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::RegisterDomain(signed_register_domain())).unwrap();
        assert_eq!(bytes[0], tx_type::REGISTER_DOMAIN);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + name (1 + 11) + domain_id
        // + owner + timestamp (5-byte varint) + empty proof (1) + pk
        // + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 1 + 11 + 32 + 32 + 5 + 1 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::RegisterDomain(signed_register_domain())
        );
    }

    #[test]
    fn update_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::UpdateDomain(signed_update_domain())).unwrap();
        assert_eq!(bytes[0], tx_type::UPDATE_DOMAIN);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + domain_id + owner
        // + sequence (1) + record_hash + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 32 + 32 + 1 + 32 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::UpdateDomain(signed_update_domain())
        );
    }

    #[test]
    fn register_tld_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::RegisterTld(signed_register_tld())).unwrap();
        assert_eq!(bytes[0], tx_type::REGISTER_TLD);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + tld name (1 + 4) + tld_id
        // + owner + timestamp (5-byte varint) + empty proof (1) + pk
        // + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 1 + 3 + 32 + 32 + 5 + 1 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::RegisterTld(signed_register_tld())
        );
    }

    #[test]
    fn transfer_tld_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::TransferTld(signed_transfer_tld())).unwrap();
        assert_eq!(bytes[0], tx_type::TRANSFER_TLD);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + tld_id + owner + new_owner
        // + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 32 + 32 + 32 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::TransferTld(signed_transfer_tld())
        );
    }

    #[test]
    fn revoke_tld_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::RevokeTld(signed_revoke_tld())).unwrap();
        assert_eq!(bytes[0], tx_type::REVOKE_TLD);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + tld_id + owner + pk
        // + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 32 + 32 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::RevokeTld(signed_revoke_tld())
        );
    }

    #[test]
    fn set_tld_open_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::SetTldOpen(signed_set_tld_open())).unwrap();
        assert_eq!(bytes[0], tx_type::SET_TLD_OPEN);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + tld_id + owner + open(1)
        // + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 32 + 32 + 1 + 32 + 64);
        // Canonical boolean: strictly 0x01 here (offset: disc+version
        // + network + tld_id + owner).
        let open_off = 1 + 1 + 14 + 32 + 32;
        assert_eq!(bytes[open_off], 0x01);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::SetTldOpen(signed_set_tld_open())
        );
    }

    #[test]
    fn set_tld_open_rejects_non_canonical_boolean() {
        // 0x02 in the open slot is a hard decode error, never coerced.
        let mut bytes = encode_to_vec(&Transaction::SetTldOpen(signed_set_tld_open())).unwrap();
        let open_off = 1 + 1 + 14 + 32 + 32;
        bytes[open_off] = 0x02;
        assert!(matches!(
            decode_complete::<Transaction>(&bytes),
            Err(ProtocolError::NonCanonical(_))
        ));
    }

    #[test]
    fn assign_domain_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::AssignDomain(signed_assign_domain())).unwrap();
        assert_eq!(bytes[0], tx_type::ASSIGN_DOMAIN);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + name (1 + 11) + domain_id
        // + owner + assignee + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 1 + 11 + 32 + 32 + 32 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::AssignDomain(signed_assign_domain())
        );
    }

    #[test]
    fn renew_domain_roundtrip_and_layout() {
        let bytes = encode_to_vec(&Transaction::RenewDomain(signed_renew_domain())).unwrap();
        assert_eq!(bytes[0], tx_type::RENEW_DOMAIN);
        assert_eq!(bytes[1], TX_FORMAT_VERSION);
        // disc + version + network (1 + 14) + domain_id + owner
        // + valid_until (5-byte varint) + pk + signature.
        assert_eq!(bytes.len(), 1 + 1 + 14 + 32 + 32 + 5 + 32 + 64);
        assert_eq!(
            decode_complete::<Transaction>(&bytes).unwrap(),
            Transaction::RenewDomain(signed_renew_domain())
        );
    }

    #[test]
    fn m8a_signing_payload_is_what_verifies() {
        // End-to-end contract for the whole M8a family: sign(payload)
        // verifies against the embedded key, tampering fails.
        for tx in [
            Transaction::TransferTld(signed_transfer_tld()),
            Transaction::RevokeTld(signed_revoke_tld()),
            Transaction::SetTldOpen(signed_set_tld_open()),
            Transaction::AssignDomain(signed_assign_domain()),
            Transaction::RenewDomain(signed_renew_domain()),
        ] {
            let payload = signing_payload(&tx).unwrap();
            let key = *tx.public_key();
            let sig = *tx.signature();
            assert!(key.verify(&payload, &sig), "{tx:?}");
            let mut tampered = payload.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 0x01;
            assert!(!key.verify(&tampered, &sig), "{tx:?}");
        }
    }

    #[test]
    fn m8a_truncated_and_corrupted_never_panics() {
        for tx in [
            Transaction::TransferTld(signed_transfer_tld()),
            Transaction::RevokeTld(signed_revoke_tld()),
            Transaction::SetTldOpen(signed_set_tld_open()),
            Transaction::AssignDomain(signed_assign_domain()),
            Transaction::RenewDomain(signed_renew_domain()),
        ] {
            let bytes = encode_to_vec(&tx).unwrap();
            for end in 0..bytes.len() {
                assert!(decode_complete::<Transaction>(&bytes[..end]).is_err());
            }
            for i in 0..bytes.len() {
                for mask in [0x01u8, 0x80, 0xff] {
                    let mut corrupted = bytes.clone();
                    corrupted[i] ^= mask;
                    let _ = decode_complete::<Transaction>(&corrupted);
                }
            }
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        for tx in [
            Transaction::RegisterDomain(signed_register_domain()),
            Transaction::UpdateDomain(signed_update_domain()),
            Transaction::RegisterTld(signed_register_tld()),
        ] {
            assert_eq!(encode_to_vec(&tx).unwrap(), encode_to_vec(&tx).unwrap());
        }
    }

    #[test]
    fn signing_payload_excludes_the_signature() {
        let sk = key(1);
        let unsigned = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            name(),
            42,
            Proof::from_bytes(vec![0xaa; 4]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = signing_payload(&unsigned).unwrap();
        // prefix + disc + version + network + name + domain + owner
        // + timestamp + proof + pk; no signature bytes.
        assert_eq!(
            payload.len(),
            TX_SIG_PREFIX.len() + 1 + 1 + 14 + 1 + 11 + 32 + 32 + 1 + 1 + 4 + 32
        );
        assert!(payload.starts_with(TX_SIG_PREFIX));
        // Changing the signature never changes the payload…
        let mut resigned = unsigned.clone();
        let sig = key(2).sign(&payload);
        if let Transaction::RegisterDomain(tx) = &mut resigned {
            tx.signature = sig;
        }
        assert_eq!(signing_payload(&resigned).unwrap(), payload);
        // …but changing any signed field does — including the name.
        if let Transaction::RegisterDomain(tx) = &mut resigned {
            tx.timestamp += 1;
        }
        assert_ne!(signing_payload(&resigned).unwrap(), payload);
    }

    #[test]
    fn register_signing_payload_covers_the_name() {
        // Two Registers differing only by name produce different
        // signing payloads (and thus different signatures).
        let sk = key(1);
        let a = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            name(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let b = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new("other.uip").unwrap(),
            1,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        assert_ne!(signing_payload(&a).unwrap(), signing_payload(&b).unwrap());
    }

    #[test]
    fn signing_payload_is_what_verifies() {
        // End-to-end contract: sign(signing_payload(tx)) verifies
        // against the embedded key, tampering the payload fails.
        let sk = key(3);
        let unsigned = Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
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
    fn register_tld_signing_payload_is_what_verifies() {
        let sk = key(4);
        let unsigned = Transaction::RegisterTld(RegisterTld::register_tld_signed(
            tld_name(),
            1,
            Proof::from_bytes(Vec::new()),
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
        let tx = RegisterDomain::register_domain_signed(
            name(),
            u64::MAX,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            sk.sign(&[0]),
        );
        assert_eq!(
            decode_complete::<Transaction>(
                &encode_to_vec(&Transaction::RegisterDomain(tx.clone())).unwrap()
            )
            .unwrap(),
            Transaction::RegisterDomain(tx)
        );
    }

    #[test]
    fn u64_max_sequence_roundtrip() {
        let sk = key(1);
        let tx = UpdateDomain::update_domain_signed(
            domain_id(),
            u64::MAX,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            sk.sign(&[0]),
        );
        assert_eq!(
            decode_complete::<Transaction>(
                &encode_to_vec(&Transaction::UpdateDomain(tx.clone())).unwrap()
            )
            .unwrap(),
            Transaction::UpdateDomain(tx)
        );
    }

    #[test]
    fn wrong_version_byte_is_rejected_explicitly() {
        // Any version byte other than 0x01 is an explicit version
        // error (generic invalid-version rule).
        let mut valid = encode_to_vec(&Transaction::UpdateDomain(signed_update_domain())).unwrap();
        for bad in [0x00u8, 0x02, 0x03, 0xff] {
            let mut bytes = valid.clone();
            bytes[1] = bad;
            assert!(
                matches!(
                    decode_complete::<Transaction>(&bytes),
                    Err(ProtocolError::UnsupportedVersion(v)) if v == u64::from(bad)
                ),
                "version byte {bad:#04x}"
            );
        }
        valid.clear();
    }

    #[test]
    fn unknown_discriminant_rejected() {
        for disc in [0x00u8, 0x04, 0xff] {
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
        let raw = UpdateDomain {
            network: scone_core::TESTNET.network_id,
            domain_id: domain_id(),
            owner: test_support::owner_of(&sk.public_key()),
            sequence: 0,
            record_hash: RecordHash::from_bytes([9; 32]),
            public_key: sk.public_key(),
            signature: sk.sign(&[0]),
        };
        assert!(encode_to_vec(&Transaction::UpdateDomain(raw.clone())).is_err());

        let mut bytes = Vec::new();
        bytes.push(tx_type::UPDATE_DOMAIN);
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
        bytes.push(tx_type::REGISTER_DOMAIN);
        bytes.push(TX_FORMAT_VERSION);
        name().encode(&mut bytes).unwrap();
        domain_id().encode(&mut bytes).unwrap();
        OwnerId::from_bytes([0xab; 32]).encode(&mut bytes).unwrap(); // forged
        varint::put_u64(1, &mut bytes);
        varint::put_u64(0, &mut bytes); // empty proof
        sk.public_key().encode(&mut bytes).unwrap();
        Signature::from_bytes([0; 64]).encode(&mut bytes).unwrap();
        assert!(decode_complete::<Transaction>(&bytes).is_err());
    }

    #[test]
    fn register_name_id_mismatch_rejected_on_decode() {
        // domain_id not derived from the carried name: rejected.
        let sk = key(1);
        let mut bytes = Vec::new();
        bytes.push(tx_type::REGISTER_DOMAIN);
        bytes.push(TX_FORMAT_VERSION);
        name().encode(&mut bytes).unwrap();
        DomainId::from_name(&DomainName::new("other.uip").unwrap())
            .encode(&mut bytes)
            .unwrap(); // forged id
        test_support::owner_of(&sk.public_key())
            .encode(&mut bytes)
            .unwrap();
        varint::put_u64(1, &mut bytes);
        varint::put_u64(0, &mut bytes);
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
        bytes.push(tx_type::REGISTER_DOMAIN);
        bytes.push(TX_FORMAT_VERSION);
        scone_core::NetworkId::TESTNET.encode(&mut bytes).unwrap();
        name().encode(&mut bytes).unwrap();
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
        let mut tx = signed_register_domain();
        tx.proof = Proof::from_bytes(vec![0xaa; limits::MAX_PROOF_LEN]);
        assert!(encode_to_vec(&Transaction::RegisterDomain(tx.clone())).is_ok());

        tx.proof = Proof::from_bytes(vec![0xaa; limits::MAX_PROOF_LEN + 1]);
        assert!(matches!(
            encode_to_vec(&Transaction::RegisterDomain(tx)),
            Err(ProtocolError::LimitExceeded("proof length"))
        ));
    }

    #[test]
    fn truncated_transaction_rejected() {
        for tx in [
            Transaction::UpdateDomain(signed_update_domain()),
            Transaction::RegisterTld(signed_register_tld()),
        ] {
            let bytes = encode_to_vec(&tx).unwrap();
            for end in 0..bytes.len() {
                assert!(decode_complete::<Transaction>(&bytes[..end]).is_err());
            }
        }
    }

    #[test]
    fn corrupted_transaction_never_panics() {
        for tx in [
            Transaction::UpdateDomain(signed_update_domain()),
            Transaction::RegisterTld(signed_register_tld()),
        ] {
            let bytes = encode_to_vec(&tx).unwrap();
            for i in 0..bytes.len() {
                for mask in [0x01u8, 0x80, 0xff] {
                    let mut corrupted = bytes.clone();
                    corrupted[i] ^= mask;
                    let _ = decode_complete::<Transaction>(&corrupted);
                }
            }
        }
    }

    // --- Pinned wire fixtures (regenerated at M7b; any change to the
    // format breaks these instead of silently renumbering) ---

    #[test]
    fn register_tld_pinned_wire_prefix() {
        // Deterministic prefix of the canonical encoding of a
        // RegisterTld("uip", ts=1, empty proof, seed-1 key, testnet):
        // disc, version, network, tld name, tld_id.
        let bytes = encode_to_vec(&Transaction::RegisterTld(signed_register_tld())).unwrap();
        // Arbitrary opaque discriminants (docs/technical/transactions.md).
        assert_eq!(bytes[0], 0x93);
        assert_eq!(bytes[1], 0x01);
        // Network field: varint length 13 + "scone-testnet" (M8b).
        assert_eq!(&bytes[2..16], b"\x0dscone-testnet");
        // TLD name: varint length 3 + "uip" (M8b).
        assert_eq!(&bytes[16..20], b"\x03uip");
        // TldId("uip") — pinned derivation vector (docs/general/naming.md).
        assert_eq!(
            &bytes[20..52],
            hex("ad5a86d68643d5c22d6a959bb1a315530c77dfda241f1ac1a8107450f3fab25e")
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
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
