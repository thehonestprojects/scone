//! DNS record data.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Result, SconeError};
use crate::id::DomainId;
use crate::name::DomainName;
use crate::owner::OwnerId;

/// Payload of one DNS resource record.
///
/// Extensible by design: future record types are added as variants
/// (non-exhaustive matching is expected), and [`RecordData::Unknown`]
/// preserves unrecognized types when decoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordData {
    /// IPv4 host address.
    A(Ipv4Addr),
    /// IPv6 host address.
    Aaaa(Ipv6Addr),
    /// Canonical name alias.
    Cname(DomainName),
    /// Mail exchange.
    Mx {
        preference: u16,
        exchange: DomainName,
    },
    /// Free-form text.
    Txt(String),
    /// Delegation name server.
    Ns(DomainName),
    /// Unrecognized type, kept as raw data for forward compatibility.
    Unknown { type_code: u16, data: Vec<u8> },
}

/// The complete DNS data of a domain at a given
/// [`sequence`](DnsRecord::sequence).
///
/// Not stored on-chain: the blockchain keeps only the
/// [`RecordHash`](crate::transaction::RecordHash) (see
/// [`crate::transaction::Update`]); the full signed record is published in
/// the DHT.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsRecord {
    /// Domain this record set belongs to.
    pub domain_id: DomainId,
    /// Monotonic version; must match the blockchain's latest sequence.
    pub sequence: u64,
    /// Expiration as a Unix timestamp (seconds); `0` means no expiration.
    pub expiration: u64,
    /// The record set.
    pub records: Vec<RecordData>,
}

impl DnsRecord {
    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// - [`SconeError::InvalidSequence`] if `sequence` is `0`
    /// - [`SconeError::InvalidRecord`] if `records` is empty
    pub fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(SconeError::InvalidSequence(0));
        }
        if self.records.is_empty() {
            return Err(SconeError::InvalidRecord("empty record set".into()));
        }
        Ok(())
    }
}

/// Opaque signature bytes over a [`DnsRecord`].
///
/// Created and verified by `scone-crypto` (planned scheme: Ed25519) over a
/// canonical encoding to be defined by `scone-protocol`. Opaque here so
/// the core stays signature-scheme-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Wraps raw signature bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Raw signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A [`DnsRecord`] signed by its owner.
///
/// Verification model (to be implemented in `scone-crypto` + the future
/// blockchain): `record + owner + signature` must verify against the key
/// registered for the owner of `domain_id` on-chain, and the record hash
/// must match the chain's latest `record_hash`. DHT data is untrusted
/// until verified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignedDnsRecord {
    pub record: DnsRecord,
    pub owner: OwnerId,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn record() -> DnsRecord {
        DnsRecord {
            domain_id: domain_id(),
            sequence: 1,
            expiration: 0,
            records: vec![RecordData::A("192.0.2.1".parse().unwrap())],
        }
    }

    #[test]
    fn valid_record_passes_validation() {
        assert!(record().validate().is_ok());
    }

    #[test]
    fn zero_sequence_is_invalid() {
        let mut r = record();
        r.sequence = 0;
        assert!(matches!(r.validate(), Err(SconeError::InvalidSequence(0))));
    }

    #[test]
    fn empty_record_set_is_invalid() {
        let mut r = record();
        r.records.clear();
        assert!(matches!(r.validate(), Err(SconeError::InvalidRecord(_))));
    }

    #[test]
    fn record_data_holds_all_variants() {
        let name = DomainName::new("example.uip").unwrap();
        let r = DnsRecord {
            domain_id: domain_id(),
            sequence: 7,
            expiration: 1_800_000_000,
            records: vec![
                RecordData::A("192.0.2.1".parse().unwrap()),
                RecordData::Aaaa("2001:db8::1".parse().unwrap()),
                RecordData::Cname(name.clone()),
                RecordData::Mx {
                    preference: 10,
                    exchange: name.clone(),
                },
                RecordData::Txt("hello".into()),
                RecordData::Ns(name.clone()),
                RecordData::Unknown {
                    type_code: 99,
                    data: vec![1, 2, 3],
                },
            ],
        };
        assert!(r.validate().is_ok());
        assert_eq!(r.records.len(), 7);
    }

    #[test]
    fn signed_record_holds_fields() {
        let owner = OwnerId::from_bytes([7; 32]);
        let signed = SignedDnsRecord {
            record: record(),
            owner,
            signature: Signature::from_bytes(vec![1, 2, 3]),
        };
        assert_eq!(signed.owner, owner);
        assert_eq!(signed.signature.as_bytes(), &[1, 2, 3]);
    }
}
