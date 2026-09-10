//! [`Encode`]/[`Decode`] traits and shared byte-level primitives.

use crate::error::{ProtocolError, Result};
use crate::varint;

/// Canonical binary encoding.
///
/// Appends the encoding of `self` to `out`. On error, `out` may contain
/// partial bytes; callers must discard it.
pub trait Encode {
    /// Appends the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()>;
}

/// Canonical binary decoding.
///
/// Reads a value from the front of `input`, advancing it; parsing without
/// allocation is possible wherever the type allows it.
pub trait Decode: Sized {
    /// Reads a value from the front of `input`.
    fn decode(input: &mut &[u8]) -> Result<Self>;
}

/// Encodes `value` into a fresh [`Vec`].
pub fn encode_to_vec<T: Encode + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value.encode(&mut out)?;
    Ok(out)
}

/// Decodes a value and rejects trailing bytes.
///
/// # Errors
///
/// Returns [`ProtocolError::TrailingBytes`] if `input` is not fully
/// consumed.
pub fn decode_complete<T: Decode>(input: &[u8]) -> Result<T> {
    let mut cursor = input;
    let value = T::decode(&mut cursor)?;
    if !cursor.is_empty() {
        return Err(ProtocolError::TrailingBytes(cursor.len()));
    }
    Ok(value)
}

// Fixed-width unsigned integers go through minimal varints; decoding
// rejects values that do not fit the target type (canonical form).

impl Encode for u64 {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        varint::put_u64(*self, out);
        Ok(())
    }
}

impl Decode for u64 {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        varint::take_u64(input)
    }
}

impl Encode for u32 {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        varint::put_u64(u64::from(*self), out);
        Ok(())
    }
}

impl Decode for u32 {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        u32::try_from(varint::take_u64(input)?)
            .map_err(|_| ProtocolError::IntegerOutOfRange("value exceeds u32"))
    }
}

impl Encode for u16 {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        varint::put_u64(u64::from(*self), out);
        Ok(())
    }
}

impl Decode for u16 {
    fn decode(input: &mut &[u8]) -> Result<Self> {
        u16::try_from(varint::take_u64(input)?)
            .map_err(|_| ProtocolError::IntegerOutOfRange("value exceeds u16"))
    }
}

/// Reads a leading discriminator byte.
pub(crate) fn take_u8(input: &mut &[u8]) -> Result<u8> {
    let byte = *input.first().ok_or(ProtocolError::Truncated)?;
    *input = &input[1..];
    Ok(byte)
}

/// Appends `bytes` prefixed by its varint length, after checking `max`.
pub(crate) fn put_bounded(
    bytes: &[u8],
    max: usize,
    what: &'static str,
    out: &mut Vec<u8>,
) -> Result<()> {
    if bytes.len() > max {
        return Err(ProtocolError::LimitExceeded(what));
    }
    varint::put_u64(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Reads a length-prefixed byte string, checking `max` **before** any
/// allocation; returns a zero-copy borrow of the input.
pub(crate) fn take_bytes<'a>(
    input: &mut &'a [u8],
    max: usize,
    what: &'static str,
) -> Result<&'a [u8]> {
    let len = varint::take_u64(input)?;
    if len > max as u64 {
        return Err(ProtocolError::LimitExceeded(what));
    }
    let len = len as usize;
    if input.len() < len {
        return Err(ProtocolError::Truncated);
    }
    let (bytes, rest) = input.split_at(len);
    *input = rest;
    Ok(bytes)
}

/// Reads a length-prefixed UTF-8 string bounded by `max`.
pub(crate) fn take_string(input: &mut &[u8], max: usize, what: &'static str) -> Result<String> {
    let bytes = take_bytes(input, max, what)?;
    std::str::from_utf8(bytes)
        .map_err(|_| ProtocolError::InvalidUtf8)
        .map(str::to_owned)
}

/// Appends a fixed-size array without prefix.
pub(crate) fn put_array<const N: usize>(bytes: &[u8; N], out: &mut Vec<u8>) {
    out.extend_from_slice(bytes);
}

/// Reads a fixed-size array without prefix.
pub(crate) fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
    if input.len() < N {
        return Err(ProtocolError::Truncated);
    }
    let (head, rest) = input.split_at(N);
    let mut array = [0u8; N];
    array.copy_from_slice(head);
    *input = rest;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_complete_rejects_trailing_bytes() {
        assert_eq!(
            decode_complete::<u64>(&[0x05, 0x00]),
            Err(ProtocolError::TrailingBytes(1))
        );
    }

    #[test]
    fn decode_complete_accepts_exact_input() {
        assert_eq!(decode_complete::<u64>(&[0x05]).unwrap(), 5);
    }

    #[test]
    fn integer_ranges_enforced() {
        // 65536 does not fit u16.
        assert!(matches!(
            decode_complete::<u16>(&[0x80, 0x80, 0x04]),
            Err(ProtocolError::IntegerOutOfRange(_))
        ));
        // 2^32 does not fit u32.
        assert!(matches!(
            decode_complete::<u32>(&[0x80, 0x80, 0x80, 0x80, 0x10]),
            Err(ProtocolError::IntegerOutOfRange(_))
        ));
    }

    #[test]
    fn take_bytes_enforces_limit_before_allocation() {
        // Announces 4097 bytes but provides none: must fail on the limit,
        // not on the missing payload.
        let mut announced = Vec::new();
        varint::put_u64(4097, &mut announced);
        let mut input = announced.as_slice();
        assert!(matches!(
            take_bytes(&mut input, 4096, "test limit"),
            Err(ProtocolError::LimitExceeded("test limit"))
        ));
    }

    #[test]
    fn take_bytes_detects_truncation() {
        let mut input = [0x05u8, 0x01, 0x02].as_slice();
        assert!(matches!(
            take_bytes(&mut input, 16, "test limit"),
            Err(ProtocolError::Truncated)
        ));
    }

    #[test]
    fn take_string_rejects_invalid_utf8() {
        let mut input = [0x02u8, 0xff, 0xfe].as_slice();
        assert!(matches!(
            take_string(&mut input, 16, "test string"),
            Err(ProtocolError::InvalidUtf8)
        ));
    }

    #[test]
    fn take_array_detects_truncation() {
        let mut input = [1u8, 2, 3].as_slice();
        assert!(matches!(
            take_array::<4>(&mut input),
            Err(ProtocolError::Truncated)
        ));
    }
}
