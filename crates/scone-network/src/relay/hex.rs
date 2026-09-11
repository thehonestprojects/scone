//! Strict lowercase-hex helpers shared by the relay modules.
//!
//! `hex_decode` is the bounded, error-typed decode used on RPC
//! inputs; `hex` renders bytes as lowercase hex. Extracted verbatim
//! from `relay.rs` (pass 2 refactor), unit tests included.

use crate::error::{NetworkError, Result};

/// Lowercase hex of raw bytes.
pub(super) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Strict hex decode (bounded by the caller).
pub(super) fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetworkError::InvalidRpc("bad hex".into()));
    }
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| NetworkError::InvalidRpc("bad hex".into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers_roundtrip() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("DEAD").unwrap(), vec![0xde, 0xad]);
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("").unwrap().is_empty());
    }
}
