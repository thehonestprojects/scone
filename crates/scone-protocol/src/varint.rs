//! Minimal LEB128 varints.
//!
//! The only integer encoding of the wire format (see `/docs/protocol.md`):
//! base-128, least-significant 7-bit group first, high bit set on every
//! byte but the last. Encodings must be **minimal** — [`take_u64`]
//! rejects overlong forms — so a value has exactly one valid byte
//! sequence, which is required for canonical hashing and signing.
//!
//! ```text
//! 0        -> 00
//! 127      -> 7f
//! 128      -> 80 01
//! u64::MAX -> ff ff ff ff ff ff ff ff ff 01
//! ```

use crate::error::{ProtocolError, Result};

/// Maximum encoded length of a `u64` (ceil(64/7) = 10 bytes).
pub const MAX_VARINT_LEN: usize = 10;

/// Appends the minimal encoding of `value`.
pub fn put_u64(value: u64, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Reads a minimal-canonical `u64` from the front of `input`.
///
/// # Errors
///
/// - [`ProtocolError::Truncated`] if the input ends mid-varint;
/// - [`ProtocolError::InvalidVarint`] if the varint is non-minimal,
///   overflows `u64` or exceeds [`MAX_VARINT_LEN`] bytes.
pub fn take_u64(input: &mut &[u8]) -> Result<u64> {
    let mut value: u64 = 0;
    for i in 0..MAX_VARINT_LEN {
        let byte = *input.first().ok_or(ProtocolError::Truncated)?;
        *input = &input[1..];
        if byte & 0x80 == 0 {
            let last = u64::from(byte);
            if i == MAX_VARINT_LEN - 1 && last > 1 {
                // 10th byte: only bit 63 fits in a u64.
                return Err(ProtocolError::InvalidVarint("u64 overflow"));
            }
            if i > 0 && last == 0 {
                return Err(ProtocolError::InvalidVarint("non-minimal encoding"));
            }
            return Ok(value | (last << (7 * i)));
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
    }
    Err(ProtocolError::InvalidVarint("longer than 10 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(bytes: &[u8]) -> Result<u64> {
        let mut input = bytes;
        take_u64(&mut input)
    }

    fn enc(value: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        put_u64(value, &mut buf);
        buf
    }

    #[test]
    fn roundtrip_boundaries_and_range() {
        let values = [
            0u64,
            1,
            127,
            128,
            255,
            16383,
            16384,
            1 << 31,
            1 << 32,
            1 << 63,
            u64::MAX,
        ];
        for value in values.into_iter().chain(0..=1000) {
            let bytes = enc(value);
            let mut input = bytes.as_slice();
            assert_eq!(take_u64(&mut input).unwrap(), value);
            assert!(input.is_empty(), "all bytes consumed for {value}");
        }
    }

    #[test]
    fn known_encodings() {
        assert_eq!(enc(0), [0x00]);
        assert_eq!(enc(1), [0x01]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(255), [0xff, 0x01]);
        assert_eq!(enc(16384), [0x80, 0x80, 0x01]);
        assert_eq!(enc(u64::MAX), [vec![0xff; 9], vec![0x01]].concat());
    }

    #[test]
    fn encoding_is_deterministic() {
        for value in [0u64, 300, u64::MAX] {
            assert_eq!(enc(value), enc(value));
        }
    }

    #[test]
    fn rejects_non_minimal() {
        // 0 encoded on two bytes.
        assert!(matches!(
            take(&[0x80, 0x00]),
            Err(ProtocolError::InvalidVarint(_))
        ));
        // 127 encoded on two bytes.
        assert!(matches!(
            take(&[0xff, 0x00]),
            Err(ProtocolError::InvalidVarint(_))
        ));
    }

    #[test]
    fn rejects_overflow() {
        // 10th byte would set bits beyond bit 63.
        let bytes = [vec![0xff; 9], vec![0x02]].concat();
        assert!(matches!(take(&bytes), Err(ProtocolError::InvalidVarint(_))));
    }

    #[test]
    fn rejects_too_long() {
        assert!(matches!(
            take(&[0xff; 10]),
            Err(ProtocolError::InvalidVarint(_))
        ));
    }

    #[test]
    fn rejects_truncated() {
        assert!(matches!(take(&[]), Err(ProtocolError::Truncated)));
        assert!(matches!(take(&[0x80]), Err(ProtocolError::Truncated)));
        assert!(matches!(take(&[0xff; 5]), Err(ProtocolError::Truncated)));
    }
}
