//! Wire encoding of DNS record data (DHT side of the protocol).
//!
//! Full DNS records never enter the blockchain: they are exchanged over
//! the DHT (`GetRecord`/`Record` messages) and committed on-chain through
//! their [`RecordHash`](scone_core::RecordHash) only (see
//! `/docs/protocol.md`).

use std::net::{Ipv4Addr, Ipv6Addr};

use scone_core::{
    DnsRecord, DomainId, DomainName, OwnerId, RecordData, SconeError, Signature, SignedDnsRecord,
};

use crate::codec::{self, Decode, Encode, encode_to_vec};
use crate::error::{ProtocolError, Result};
use crate::limits;
use crate::varint;

/// DNS type codes (RFC 1035 / IANA registry) used as wire discriminants
/// for [`RecordData`].
pub mod dns_type {
    /// IPv4 host address.
    pub const A: u16 = 1;
    /// Delegation name server.
    pub const NS: u16 = 2;
    /// Canonical name alias.
    pub const CNAME: u16 = 5;
    /// Mail exchange.
    pub const MX: u16 = 15;
    /// Free-form text.
    pub const TXT: u16 = 16;
    /// IPv6 host address.
    pub const AAAA: u16 = 28;
}

fn is_known(code: u16) -> bool {
    matches!(
        code,
        dns_type::A
            | dns_type::NS
            | dns_type::CNAME
            | dns_type::MX
            | dns_type::TXT
            | dns_type::AAAA
    )
}

fn put_type(code: u16, out: &mut Vec<u8>) {
    varint::put_u64(u64::from(code), out);
}

fn take_type(input: &mut &[u8]) -> Result<u16> {
    let code = varint::take_u64(input)?;
    u16::try_from(code).map_err(|_| ProtocolError::IntegerOutOfRange("record type code"))
}

// RecordData = type.v || payload(type)

impl Encode for RecordData {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::A(ip) => {
                put_type(dns_type::A, out);
                codec::put_array(&ip.octets(), out);
            }
            Self::Aaaa(ip) => {
                put_type(dns_type::AAAA, out);
                codec::put_array(&ip.octets(), out);
            }
            Self::Cname(name) => {
                put_type(dns_type::CNAME, out);
                name.encode(out)?;
            }
            Self::Mx {
                preference,
                exchange,
            } => {
                put_type(dns_type::MX, out);
                preference.encode(out)?;
                exchange.encode(out)?;
            }
            Self::Txt(text) => {
                put_type(dns_type::TXT, out);
                codec::put_bounded(text.as_bytes(), limits::MAX_TXT_LEN, "TXT length", out)?;
            }
            Self::Ns(name) => {
                put_type(dns_type::NS, out);
                name.encode(out)?;
            }
            Self::Unknown {
                type_code: code,
                data,
            } => {
                if is_known(*code) {
                    return Err(ProtocolError::Validation(SconeError::InvalidFormat(
                        "Unknown record must not carry a known type code".into(),
                    )));
                }
                put_type(*code, out);
                codec::put_bounded(
                    data,
                    limits::MAX_UNKNOWN_DATA,
                    "unknown record data length",
                    out,
                )?;
            }
        }
        Ok(())
    }
}

impl Decode for RecordData {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(match take_type(input)? {
            dns_type::A => Self::A(Ipv4Addr::from(codec::take_array::<4>(input)?)),
            dns_type::AAAA => Self::Aaaa(Ipv6Addr::from(codec::take_array::<16>(input)?)),
            dns_type::CNAME => Self::Cname(DomainName::decode(input)?),
            dns_type::MX => Self::Mx {
                preference: u16::decode(input)?,
                exchange: DomainName::decode(input)?,
            },
            dns_type::TXT => Self::Txt(codec::take_string(
                input,
                limits::MAX_TXT_LEN,
                "TXT length",
            )?),
            dns_type::NS => Self::Ns(DomainName::decode(input)?),
            code => Self::Unknown {
                type_code: code,
                data: codec::take_bytes(
                    input,
                    limits::MAX_UNKNOWN_DATA,
                    "unknown record data length",
                )?
                .to_vec(),
            },
        })
    }
}

// Signature = bytes (bounded, opaque; scheme lives in scone-crypto)

impl Encode for Signature {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_bounded(
            self.as_bytes(),
            limits::MAX_SIGNATURE_LEN,
            "signature length",
            out,
        )
    }
}

impl Decode for Signature {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self::from_bytes(
            codec::take_bytes(input, limits::MAX_SIGNATURE_LEN, "signature length")?.to_vec(),
        ))
    }
}

// DnsRecord = domain_id[32] || sequence.v || expiration.v || count.v || records…
//
// Canonical rule: the record set is an ORDER-INDEPENDENT collection. It is
// encoded sorted by the lexicographic order of each record's individual
// encoding, strictly increasing (duplicates rejected). The original Vec
// order is therefore NOT the wire order.

impl Encode for DnsRecord {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.validate().map_err(ProtocolError::Validation)?;
        if self.records.len() > limits::MAX_RECORDS_PER_SET {
            return Err(ProtocolError::LimitExceeded("record set size"));
        }
        self.domain_id.encode(out)?;
        varint::put_u64(self.sequence, out);
        varint::put_u64(self.expiration, out);
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(self.records.len());
        for record in &self.records {
            encoded.push(encode_to_vec(record)?);
        }
        encoded.sort();
        if encoded.windows(2).any(|w| w[0] == w[1]) {
            return Err(ProtocolError::NonCanonical("duplicate record in set"));
        }
        varint::put_u64(encoded.len() as u64, out);
        for bytes in &encoded {
            out.extend_from_slice(bytes);
        }
        Ok(())
    }
}

impl Decode for DnsRecord {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let domain_id = DomainId::decode(input)?;
        let sequence = u64::decode(input)?;
        let expiration = u64::decode(input)?;
        let count = varint::take_u64(input)?;
        if count > limits::MAX_RECORDS_PER_SET as u64 {
            return Err(ProtocolError::LimitExceeded("record set size"));
        }
        let mut records = Vec::with_capacity(count as usize);
        let mut previous: Vec<u8> = Vec::new();
        for _ in 0..count {
            let record = RecordData::decode(input)?;
            let encoded = encode_to_vec(&record)?;
            if encoded <= previous {
                return Err(ProtocolError::NonCanonical("record set not sorted"));
            }
            previous = encoded;
            records.push(record);
        }
        let record = Self {
            domain_id,
            sequence,
            expiration,
            records,
        };
        record.validate().map_err(ProtocolError::Validation)?;
        Ok(record)
    }
}

// SignedDnsRecord = DnsRecord || owner[32] || signature

impl Encode for SignedDnsRecord {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.record.encode(out)?;
        self.owner.encode(out)?;
        self.signature.encode(out)
    }
}

impl Decode for SignedDnsRecord {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        Ok(Self {
            record: DnsRecord::decode(input)?,
            owner: OwnerId::decode(input)?,
            signature: Signature::decode(input)?,
        })
    }
}

/// Shared test fixtures (crate-internal).
#[cfg(test)]
pub(crate) mod tests_fixtures {
    use super::*;

    pub fn name() -> DomainName {
        DomainName::new("example.uip").unwrap()
    }

    /// A multi-variant record set already in canonical (sorted) order.
    pub fn canonical_record() -> DnsRecord {
        let mut record = full_record();
        record.records.sort_by_key(|r| encode_to_vec(r).unwrap());
        record
    }

    fn full_record() -> DnsRecord {
        let name = name();
        DnsRecord {
            domain_id: DomainId::from_name(&name),
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::decode_complete;

    fn name() -> DomainName {
        DomainName::new("example.uip").unwrap()
    }

    fn record() -> DnsRecord {
        DnsRecord {
            domain_id: DomainId::from_name(&name()),
            sequence: 1,
            expiration: 0,
            records: vec![RecordData::A(Ipv4Addr::new(192, 0, 2, 1))],
        }
    }

    fn full_record() -> DnsRecord {
        let name = name();
        DnsRecord {
            domain_id: DomainId::from_name(&name),
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
        }
    }

    /// Same record set with records sorted in canonical wire order.
    fn canonical(record: &DnsRecord) -> DnsRecord {
        let mut sorted = record.clone();
        sorted.records.sort_by_key(|r| encode_to_vec(r).unwrap());
        sorted
    }

    #[test]
    fn a_record_known_bytes() {
        // type A (1) + 192.0.2.1
        assert_eq!(
            encode_to_vec(&RecordData::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
            [0x01, 192, 0, 2, 1]
        );
    }

    #[test]
    fn unknown_record_known_bytes() {
        // type 99 + len 3 + 01 02 03
        assert_eq!(
            encode_to_vec(&RecordData::Unknown {
                type_code: 99,
                data: vec![1, 2, 3]
            })
            .unwrap(),
            [0x63, 0x03, 1, 2, 3]
        );
    }

    #[test]
    fn all_variants_roundtrip() {
        let record = canonical(&full_record());
        assert_eq!(
            decode_complete::<DnsRecord>(&encode_to_vec(&record).unwrap()).unwrap(),
            record
        );
        for rec in &full_record().records {
            assert_eq!(
                decode_complete::<RecordData>(&encode_to_vec(rec).unwrap()).unwrap(),
                *rec
            );
        }
    }

    #[test]
    fn record_encoding_is_deterministic() {
        assert_eq!(
            encode_to_vec(&full_record()).unwrap(),
            encode_to_vec(&full_record()).unwrap()
        );
    }

    #[test]
    fn record_set_permutations_encode_identically() {
        let mut permuted = full_record();
        permuted.records.reverse();
        assert_eq!(
            encode_to_vec(&permuted).unwrap(),
            encode_to_vec(&full_record()).unwrap()
        );
    }

    #[test]
    fn unsorted_record_set_rejected_on_decode() {
        let mut bytes = Vec::new();
        record().domain_id.encode(&mut bytes).unwrap();
        varint::put_u64(1, &mut bytes); // sequence
        varint::put_u64(0, &mut bytes); // expiration
        varint::put_u64(2, &mut bytes); // count
        bytes.extend_from_slice(&encode_to_vec(&RecordData::A(Ipv4Addr::new(9, 9, 9, 9))).unwrap());
        bytes.extend_from_slice(&encode_to_vec(&RecordData::A(Ipv4Addr::new(1, 1, 1, 1))).unwrap());
        assert!(matches!(
            decode_complete::<DnsRecord>(&bytes),
            Err(ProtocolError::NonCanonical("record set not sorted"))
        ));
    }

    #[test]
    fn duplicate_records_rejected() {
        let mut record = record();
        record
            .records
            .push(RecordData::A(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(matches!(
            encode_to_vec(&record),
            Err(ProtocolError::NonCanonical("duplicate record in set"))
        ));
    }

    #[test]
    fn unknown_with_known_type_code_rejected() {
        let bad = RecordData::Unknown {
            type_code: dns_type::A,
            data: vec![1, 2, 3, 4],
        };
        assert!(encode_to_vec(&bad).is_err());
    }

    #[test]
    fn empty_record_set_rejected() {
        let mut record = record();
        record.records.clear();
        assert!(encode_to_vec(&record).is_err());
        // count = 0 on the wire: rejected by core validation.
        assert!(
            decode_complete::<DnsRecord>(&{
                let mut bytes = Vec::new();
                record.domain_id.encode(&mut bytes).unwrap();
                varint::put_u64(1, &mut bytes);
                varint::put_u64(0, &mut bytes);
                varint::put_u64(0, &mut bytes);
                bytes
            })
            .is_err()
        );
    }

    #[test]
    fn zero_sequence_rejected() {
        let mut record = record();
        record.sequence = 0;
        assert!(encode_to_vec(&record).is_err());
    }

    #[test]
    fn u64_max_sequence_roundtrips() {
        let mut record = record();
        record.sequence = u64::MAX;
        assert_eq!(
            decode_complete::<DnsRecord>(&encode_to_vec(&record).unwrap()).unwrap(),
            record
        );
    }

    #[test]
    fn txt_boundaries() {
        let mut record = record();
        record.records = vec![RecordData::Txt("x".repeat(limits::MAX_TXT_LEN))];
        assert!(encode_to_vec(&record).is_ok());

        record.records = vec![RecordData::Txt("x".repeat(limits::MAX_TXT_LEN + 1))];
        assert!(matches!(
            encode_to_vec(&record),
            Err(ProtocolError::LimitExceeded("TXT length"))
        ));
        // Announced-but-absent oversized TXT: limit hit before allocation.
        let mut bytes = Vec::new();
        put_type(dns_type::TXT, &mut bytes);
        varint::put_u64(limits::MAX_TXT_LEN as u64 + 1, &mut bytes);
        assert!(matches!(
            decode_complete::<RecordData>(&bytes),
            Err(ProtocolError::LimitExceeded("TXT length"))
        ));
    }

    #[test]
    fn empty_txt_allowed() {
        let record_data = RecordData::Txt(String::new());
        assert_eq!(
            decode_complete::<RecordData>(&encode_to_vec(&record_data).unwrap()).unwrap(),
            record_data
        );
    }

    #[test]
    fn record_set_size_limit_enforced() {
        // count > MAX announced on the wire: rejected before allocation.
        let mut announced = Vec::new();
        varint::put_u64(limits::MAX_RECORDS_PER_SET as u64 + 1, &mut announced);
        let mut bytes = Vec::new();
        record().domain_id.encode(&mut bytes).unwrap();
        varint::put_u64(1, &mut bytes);
        varint::put_u64(0, &mut bytes);
        bytes.extend_from_slice(&announced);
        assert!(matches!(
            decode_complete::<DnsRecord>(&bytes),
            Err(ProtocolError::LimitExceeded("record set size"))
        ));
    }

    #[test]
    fn signed_record_roundtrip() {
        let signed = SignedDnsRecord {
            record: canonical(&full_record()),
            owner: OwnerId::from_bytes([7; 32]),
            signature: Signature::from_bytes(vec![9; 64]),
        };
        assert_eq!(
            decode_complete::<SignedDnsRecord>(&encode_to_vec(&signed).unwrap()).unwrap(),
            signed
        );
    }

    #[test]
    fn signature_boundaries() {
        let mut signed = SignedDnsRecord {
            record: record(),
            owner: OwnerId::from_bytes([7; 32]),
            signature: Signature::from_bytes(vec![9; limits::MAX_SIGNATURE_LEN]),
        };
        assert!(encode_to_vec(&signed).is_ok());

        signed.signature = Signature::from_bytes(vec![9; limits::MAX_SIGNATURE_LEN + 1]);
        assert!(matches!(
            encode_to_vec(&signed),
            Err(ProtocolError::LimitExceeded("signature length"))
        ));
    }

    #[test]
    fn truncated_record_rejected() {
        let bytes = encode_to_vec(&canonical(&full_record())).unwrap();
        for end in 0..bytes.len() {
            assert!(
                decode_complete::<DnsRecord>(&bytes[..end]).is_err(),
                "prefix of len {end} must not decode"
            );
        }
    }

    #[test]
    fn corrupted_record_never_panics() {
        let bytes = encode_to_vec(&canonical(&full_record())).unwrap();
        for i in 0..bytes.len() {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut corrupted = bytes.clone();
                corrupted[i] ^= mask;
                let _ = decode_complete::<DnsRecord>(&corrupted);
                let _ = decode_complete::<RecordData>(&corrupted);
            }
        }
    }
}
