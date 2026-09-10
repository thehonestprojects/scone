//! Wire encoding of `scone-core` identifiers and names.

use scone_core::{DomainId, DomainName, OwnerId, PublicKeyRef, RecordHash};

use crate::codec::{self, Decode, Encode};
use crate::error::{ProtocolError, Result};
use crate::limits;

// 32-byte identifiers: raw bytes on the wire, no prefix, no length
// (see /docs/protocol.md). Derivation stays in `scone-core`.

macro_rules! impl_fixed_id {
    ($ty:ty) => {
        impl Encode for $ty {
            fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
                codec::put_array(self.as_bytes(), out);
                Ok(())
            }
        }

        impl Decode for $ty {
            fn decode(input: &mut &[u8]) -> Result<Self> {
                Ok(Self::from_bytes(codec::take_array(input)?))
            }
        }
    };
}

impl_fixed_id!(DomainId);
impl_fixed_id!(OwnerId);
impl_fixed_id!(PublicKeyRef);
impl_fixed_id!(RecordHash);

// Domain names: varint length + canonical UTF-8 bytes, re-validated by
// `scone-core` on decode (no duplicated naming rules).

impl Encode for DomainName {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        codec::put_bounded(
            self.canonical().as_bytes(),
            limits::MAX_NAME_LEN,
            "domain name length",
            out,
        )
    }
}

impl Decode for DomainName {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        let bytes = codec::take_bytes(input, limits::MAX_NAME_LEN, "domain name length")?;
        let name = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8)?;
        DomainName::new(name).map_err(ProtocolError::Validation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_complete, encode_to_vec};

    fn name() -> DomainName {
        DomainName::new("example.uip").unwrap()
    }

    #[test]
    fn ids_are_32_raw_bytes() {
        let bytes = encode_to_vec(&DomainId::from_bytes([5; 32])).unwrap();
        assert_eq!(bytes, vec![5u8; 32]);
        assert_eq!(
            encode_to_vec(&OwnerId::from_bytes([6; 32])).unwrap().len(),
            32
        );
        assert_eq!(
            encode_to_vec(&PublicKeyRef::from_bytes([7; 32]))
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            encode_to_vec(&RecordHash::from_bytes([8; 32]))
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn ids_roundtrip() {
        let id = DomainId::from_name(&name());
        assert_eq!(
            decode_complete::<DomainId>(&encode_to_vec(&id).unwrap()).unwrap(),
            id
        );

        let owner = OwnerId::from_bytes([1; 32]);
        assert_eq!(
            decode_complete::<OwnerId>(&encode_to_vec(&owner).unwrap()).unwrap(),
            owner
        );

        let hash = RecordHash::from_bytes([9; 32]);
        assert_eq!(
            decode_complete::<RecordHash>(&encode_to_vec(&hash).unwrap()).unwrap(),
            hash
        );
    }

    #[test]
    fn ids_truncated_rejected() {
        let bytes = encode_to_vec(&RecordHash::from_bytes([9; 32])).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_complete::<RecordHash>(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn name_encoding_is_length_prefixed_utf8() {
        let bytes = encode_to_vec(&name()).unwrap();
        let mut expected = vec![11u8]; // "example.uip".len()
        expected.extend_from_slice(b"example.uip");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn name_roundtrip() {
        assert_eq!(
            decode_complete::<DomainName>(&encode_to_vec(&name()).unwrap()).unwrap(),
            name()
        );
    }

    #[test]
    fn name_decode_revalidates_core_rules() {
        // Single label: not a valid DomainName.
        assert!(decode_complete::<DomainName>(&[0x03, b'a', b'b', b'c']).is_err());
        // Uppercase is rejected, never canonicalized.
        let upper = [0x03, b'A', b'B', b'C'];
        assert!(decode_complete::<DomainName>(&upper).is_err());
        // Non-UTF-8.
        assert!(decode_complete::<DomainName>(&[0x02, 0xff, 0xfe]).is_err());
    }

    #[test]
    fn name_length_limit_enforced() {
        let mut announced = Vec::new();
        crate::varint::put_u64(limits::MAX_NAME_LEN as u64 + 1, &mut announced);
        assert!(matches!(
            decode_complete::<DomainName>(&announced),
            Err(ProtocolError::LimitExceeded("domain name length"))
        ));
    }

    #[test]
    fn name_truncated_rejected() {
        let bytes = encode_to_vec(&name()).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_complete::<DomainName>(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn max_length_name_roundtrips() {
        // 4 labels of 61 bytes + 4 dots + 5-byte TLD = 253 bytes exactly.
        let max = format!(
            "{}.{}.{}.{}.abcde",
            "a".repeat(61),
            "b".repeat(61),
            "c".repeat(61),
            "d".repeat(61)
        );
        let name = DomainName::new(&max).unwrap();
        assert_eq!(
            decode_complete::<DomainName>(&encode_to_vec(&name).unwrap()).unwrap(),
            name
        );
    }
}
