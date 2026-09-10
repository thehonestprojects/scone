//! Canonical hashing over protocol encodings.

use scone_core::{DnsRecord, RecordHash};

use crate::codec::encode_to_vec;

/// Domain-separation prefix for [`record_hash`].
pub const RECORD_HASH_VERSION: &[u8] = b"SCONE-RECORD-V1";

/// Computes the on-chain commitment to `record`:
///
/// ```text
/// RecordHash = BLAKE3-256("SCONE-RECORD-V1" || canonical_encoding(DnsRecord))
/// ```
///
/// The hash covers the record **content only**: the owner signature (see
/// `SignedDnsRecord`) is verified separately over the same canonical
/// bytes, so the commitment never depends on the signature scheme.
///
/// # Panics
///
/// Panics if `record` fails core validation; only possible for locally
/// constructed records (decoded records are always valid).
pub fn record_hash(record: &DnsRecord) -> RecordHash {
    let encoded = encode_to_vec(record).expect("valid record");
    RecordHash::from_bytes(scone_crypto::hash256(&[RECORD_HASH_VERSION, &encoded]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::tests_fixtures as fixtures;
    use scone_core::{DomainId, RecordData};
    use std::net::Ipv4Addr;

    #[test]
    fn deterministic() {
        assert_eq!(
            record_hash(&fixtures::canonical_record()),
            record_hash(&fixtures::canonical_record())
        );
    }

    #[test]
    fn matches_documented_formula() {
        let record = fixtures::canonical_record();
        let encoded = encode_to_vec(&record).unwrap();
        let expected = scone_crypto::hash256(&[RECORD_HASH_VERSION, &encoded]);
        assert_eq!(*record_hash(&record).as_bytes(), expected);
    }

    #[test]
    fn permutation_independent() {
        let mut permuted = fixtures::canonical_record();
        permuted.records.reverse();
        assert_eq!(
            record_hash(&fixtures::canonical_record()),
            record_hash(&permuted)
        );
    }

    #[test]
    fn changes_with_content() {
        let base = fixtures::canonical_record();

        let mut other_sequence = base.clone();
        other_sequence.sequence += 1;
        assert_ne!(record_hash(&base), record_hash(&other_sequence));

        let mut other_records = base.clone();
        other_records
            .records
            .push(RecordData::A(Ipv4Addr::new(198, 51, 100, 1)));
        assert_ne!(record_hash(&base), record_hash(&other_records));

        let mut other_domain = base;
        other_domain.domain_id = DomainId::from_bytes([0xab; 32]);
        assert_ne!(
            record_hash(&fixtures::canonical_record()),
            record_hash(&other_domain)
        );
    }
}
