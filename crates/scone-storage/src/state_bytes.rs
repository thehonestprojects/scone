//! Compact storage encoding of a [`DomainState`](scone_blockchain::DomainState).
//!
//! 41 or 73 bytes depending on the 1-byte tag:
//!
//! ```text
//! DomainStateBytes = tag || owner(32) || sequence(8 BE) || record_hash?
//!   tag = 0x01, record_hash present  -> 1 + 32 + 8 + 32 = 73 bytes
//!   tag = 0x02, record_hash absent   -> 1 + 32 + 8       = 41 bytes
//! ```
//!
//! Fixed-width big-endian integers keep the encoding canonical and
//! byte-comparable. Decoding is strict: wrong tag, short buffer or
//! trailing bytes is [`StorageError::Corrupted`], never a panic.

use scone_blockchain::DomainState;
use scone_core::{DomainId, OwnerId, RecordHash};

use crate::error::{Result, StorageError};

/// Length of a `record_hash == None` encoding (tag + owner + sequence).
pub const DOMAIN_STATE_LEN_NONE: usize = 41;

/// Length of a `record_hash == Some(_)` encoding.
pub const DOMAIN_STATE_LEN_SOME: usize = DOMAIN_STATE_LEN_NONE + 32;

const TAG_WITH_HASH: u8 = 0x01;
const TAG_WITHOUT_HASH: u8 = 0x02;

/// Storage encoding of one domain's on-chain state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainStateBytes(pub [u8; DOMAIN_STATE_LEN_SOME]);

impl From<&DomainState> for DomainStateBytes {
    fn from(state: &DomainState) -> Self {
        let mut bytes = [0u8; DOMAIN_STATE_LEN_SOME];
        match state.record_hash {
            Some(hash) => {
                bytes[0] = TAG_WITH_HASH;
                bytes[1..33].copy_from_slice(state.owner.as_bytes());
                bytes[33..41].copy_from_slice(&state.sequence.to_be_bytes());
                bytes[41..73].copy_from_slice(hash.as_bytes());
            }
            None => {
                bytes[0] = TAG_WITHOUT_HASH;
                bytes[1..33].copy_from_slice(state.owner.as_bytes());
                bytes[33..41].copy_from_slice(&state.sequence.to_be_bytes());
                // bytes[41..73] stay zero; `as_encoded` truncates.
            }
        }
        Self(bytes)
    }
}

impl DomainStateBytes {
    /// The canonical encoded bytes (41 or 73 bytes long).
    #[must_use]
    pub fn as_encoded(&self) -> &[u8] {
        let len = if self.0[0] == TAG_WITH_HASH {
            DOMAIN_STATE_LEN_SOME
        } else {
            DOMAIN_STATE_LEN_NONE
        };
        &self.0[..len]
    }

    /// Strictly decodes canonical bytes into the RAM-side
    /// [`DomainState`].
    ///
    /// # Errors
    ///
    /// [`StorageError::Corrupted`] on unknown tag, wrong length or
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<DomainState> {
        let corrupted = |what: String| StorageError::Corrupted(format!("DomainStateBytes: {what}"));
        let (tag, hash) = match bytes.first() {
            Some(&TAG_WITH_HASH) if bytes.len() == DOMAIN_STATE_LEN_SOME => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[41..73]);
                (TAG_WITH_HASH, Some(RecordHash::from_bytes(hash)))
            }
            Some(&TAG_WITHOUT_HASH) if bytes.len() == DOMAIN_STATE_LEN_NONE => {
                (TAG_WITHOUT_HASH, None)
            }
            Some(&other) => {
                return Err(corrupted(format!("unknown tag {other:#04x}")));
            }
            None => return Err(corrupted("empty".into())),
        };
        let _ = tag;
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&bytes[1..33]);
        let sequence = u64::from_be_bytes(
            bytes[33..41]
                .try_into()
                .map_err(|_| corrupted("sequence".into()))?,
        );
        Ok(DomainState {
            owner: OwnerId::from_bytes(owner),
            sequence,
            record_hash: hash,
        })
    }
}

/// Reads a stored `(DomainId -> DomainStateBytes)` entry, strictly.
pub(crate) fn decode_domain_entry(
    key: &[u8],
    value: &[u8],
) -> Result<(DomainId, DomainStateBytes)> {
    let corrupted = || StorageError::Corrupted("domains entry".into());
    let key: &[u8; 32] = key.try_into().map_err(|_| corrupted())?;
    let mut bytes = [0u8; DOMAIN_STATE_LEN_SOME];
    let n = value.len();
    if n != DOMAIN_STATE_LEN_NONE && n != DOMAIN_STATE_LEN_SOME {
        return Err(corrupted());
    }
    bytes[..n].copy_from_slice(value);
    Ok((DomainId::from_bytes(*key), DomainStateBytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(record_hash: Option<RecordHash>) -> DomainState {
        DomainState {
            owner: OwnerId::from_bytes([7; 32]),
            sequence: 0x0102_0304_0506_0708,
            record_hash,
        }
    }

    fn hash(seed: u8) -> RecordHash {
        RecordHash::from_bytes([seed; 32])
    }

    #[test]
    fn roundtrip_with_record_hash() {
        let original = state(Some(hash(9)));
        let encoded = DomainStateBytes::from(&original);
        assert_eq!(encoded.as_encoded().len(), DOMAIN_STATE_LEN_SOME);
        assert_eq!(encoded.as_encoded()[0], 1);
        assert_eq!(
            DomainStateBytes::decode(encoded.as_encoded()).unwrap(),
            original
        );
    }

    #[test]
    fn roundtrip_without_record_hash() {
        let original = state(None);
        let encoded = DomainStateBytes::from(&original);
        assert_eq!(encoded.as_encoded().len(), DOMAIN_STATE_LEN_NONE);
        assert_eq!(encoded.as_encoded()[0], 2);
        assert_eq!(
            DomainStateBytes::decode(encoded.as_encoded()).unwrap(),
            original
        );
    }

    #[test]
    fn zero_sequence_and_zero_owner_roundtrip() {
        let original = DomainState {
            owner: OwnerId::from_bytes([0; 32]),
            sequence: 0,
            record_hash: None,
        };
        let encoded = DomainStateBytes::from(&original);
        assert_eq!(
            DomainStateBytes::decode(encoded.as_encoded()).unwrap(),
            original
        );
    }

    #[test]
    fn u64_max_sequence_roundtrip() {
        let original = DomainState {
            owner: OwnerId::from_bytes([1; 32]),
            sequence: u64::MAX,
            record_hash: Some(hash(3)),
        };
        let encoded = DomainStateBytes::from(&original);
        assert_eq!(
            DomainStateBytes::decode(encoded.as_encoded()).unwrap(),
            original
        );
    }

    #[test]
    fn empty_input_is_corrupted() {
        assert!(matches!(
            DomainStateBytes::decode(&[]),
            Err(StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn unknown_tag_is_corrupted() {
        let mut encoded = DomainStateBytes::from(&state(None));
        encoded.0[0] = 0x03;
        assert!(matches!(
            DomainStateBytes::decode(encoded.as_encoded()),
            Err(StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn trailing_bytes_are_corrupted() {
        let encoded = DomainStateBytes::from(&state(None));
        let mut extended = encoded.as_encoded().to_vec();
        extended.push(0);
        assert!(matches!(
            DomainStateBytes::decode(&extended),
            Err(StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn truncated_input_is_corrupted() {
        let encoded = DomainStateBytes::from(&state(Some(hash(1))));
        assert!(matches!(
            DomainStateBytes::decode(&encoded.as_encoded()[..20]),
            Err(StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn decode_domain_entry_roundtrip() {
        let key = [0xab; 32];
        let encoded = DomainStateBytes::from(&state(Some(hash(5))));
        let (domain, back) = decode_domain_entry(&key, encoded.as_encoded()).unwrap();
        assert_eq!(domain.as_bytes(), &key);
        assert_eq!(back.as_encoded(), encoded.as_encoded());
    }

    #[test]
    fn decode_domain_entry_rejects_bad_key() {
        let encoded = DomainStateBytes::from(&state(None));
        assert!(decode_domain_entry(&[0; 31], encoded.as_encoded()).is_err());
    }
}
