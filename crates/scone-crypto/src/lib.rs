//! # scone-crypto
//!
//! Cryptographic primitives for the Scone protocol.
//!
//! This crate is the lowest layer of the stack: it never depends on
//! networking, the filesystem, an async runtime, or any other Scone crate.
//! All functions operate on raw bytes so upper layers (`scone-core`,
//! `scone-protocol`) can use them without circular dependencies.
//!
//! Rule: no hand-rolled cryptography. Only well-audited algorithms and
//! implementations.
//!
//! ## Current API
//!
//! - [`hash256`]: BLAKE3-256, used for `DomainId` and record hashes.
//! - [`keys`]: Ed25519 signing keys, public keys and signatures
//!   (RFC 8032), with `verify_strict` semantics for untrusted data.
//!
//! ## Planned API (not implemented yet)
//!
//! - registration proof of work
//! - Merkle trees for block commitments

pub mod group_aead;
pub mod keys;

pub use keys::{
    InvalidKeyError, PUBLIC_KEY_SIZE, PublicKey, SIGNATURE_SIZE, SIGNING_KEY_SIZE, Signature,
    SigningKey,
};

/// Hashes the concatenation of `parts` with BLAKE3 and returns the 32-byte
/// digest.
///
/// Domain separation is achieved by passing a distinct prefix as the first
/// part (e.g. `b"SCONE-DOMAIN-V1"`). Callers must pass canonical,
/// unambiguous parts: BLAKE3 is a streaming hash, so `hash256(&[b"ab",
/// b"c"]) == hash256(&[b"a", b"bc"])`.
pub fn hash256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_is_deterministic() {
        assert_eq!(
            hash256(&[b"SCONE-DOMAIN-V1", b"example.uip"]),
            hash256(&[b"SCONE-DOMAIN-V1", b"example.uip"])
        );
    }

    #[test]
    fn hash256_separates_inputs() {
        assert_ne!(
            hash256(&[b"SCONE-DOMAIN-V1", b"example.uip"]),
            hash256(&[b"SCONE-DOMAIN-V1", b"other.uip"])
        );
        assert_ne!(hash256(&[b"A", b"x"]), hash256(&[b"B", b"x"]));
    }

    #[test]
    fn hash256_of_nothing_matches_blake3_of_empty() {
        assert_eq!(hash256(&[]), *blake3::hash(b"").as_bytes());
    }
}
