//! Ed25519 signing keys, public keys and signatures (RFC 8032).
//!
//! Thin, type-safe wrappers around [`ed25519_dalek`]: the Scone protocol
//! never manipulates raw key bytes outside of encode/decode boundaries.
//!
//! Hard rules honoured here:
//!
//! - no hand-rolled cryptography — everything delegates to the audited
//!   `ed25519-dalek` implementation (its default `zeroize` feature is
//!   kept enabled, so [`SigningKey`] is zeroized on drop);
//! - pure crate: no networking, no filesystem, no async, no other Scone
//!   crate;
//! - no panic on untrusted input: decoding goes through
//!   [`Result`](std::result::Result)-returning constructors.
//!
//! [`Signature`] and [`PublicKey`] are distinct types from their
//! `ed25519-dalek` counterparts on purpose: protocol layers exchange raw
//! bytes and must use the `from_bytes` / `to_bytes` pairs at their
//! boundaries.

use ed25519_dalek::SigningKey as DalekSigningKey;

/// Size in bytes of an Ed25519 secret key (seed).
pub const SIGNING_KEY_SIZE: usize = 32;

/// Size in bytes of an Ed25519 public key.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size in bytes of an Ed25519 signature.
pub const SIGNATURE_SIZE: usize = 64;

/// An Ed25519 signing key (32-byte seed + derived public key).
///
/// Zeroized on drop by `ed25519-dalek` (default `zeroize` feature);
/// [`Debug`](std::fmt::Debug) never exposes the seed. The key is never
/// written to disk or the wire in the clear: `scone-keystore` stores it
/// encrypted, `scone-protocol` only ever exchanges public keys and
/// signatures.
#[derive(Clone)]
pub struct SigningKey(DalekSigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose secret key material in logs.
        f.write_str("SigningKey(<secret>)")
    }
}

impl SigningKey {
    /// Generates a fresh key from the operating system CSPRNG.
    pub fn generate() -> Self {
        use ed25519_dalek::rand_core::UnwrapErr;

        // `UnwrapErr` panics if the OS entropy source fails; there is no
        // safe fallback from missing entropy (same semantics as
        // `rand::rngs::OsRng`).
        let mut rng = UnwrapErr(getrandom::SysRng);
        Self(DalekSigningKey::generate(&mut rng))
    }

    /// Wraps a 32-byte seed.
    ///
    /// Any 32 bytes are a valid seed per RFC 8032 (clamping happens
    /// internally), so this cannot fail.
    pub fn from_bytes(bytes: [u8; SIGNING_KEY_SIZE]) -> Self {
        Self(DalekSigningKey::from_bytes(&bytes))
    }

    /// Returns the 32-byte seed.
    ///
    /// The returned copy is NOT zeroized on drop — callers holding it
    /// must zeroize it themselves.
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Signs `payload` (PureEdDSA, RFC 8032 §5.1).
    pub fn sign(&self, payload: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        Signature(self.0.sign(payload).to_bytes())
    }
}

/// An Ed25519 public key (32 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_SIZE]);

impl PublicKey {
    /// Wraps raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidKeyError`] when `bytes` does not decode to a
    /// curve point at all (non-decompressable encoding). Note what
    /// this constructor does NOT reject: small-order points (e.g. the
    /// all-zero identity encoding) and non-canonical `y ≥ p`
    /// encodings are accepted here — strict checks live in
    /// [`PublicKey::verify`](Self::verify) (`verify_strict` rejects
    /// weak keys at verification time). Untrusted input never causes
    /// a panic.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self, InvalidKeyError> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map(|_| Self(bytes))
            .map_err(|_| InvalidKeyError)
    }

    /// Raw bytes.
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }

    /// Verifies `signature` over `payload`.
    ///
    /// Uses `verify_strict`: malleable and non-canonical signatures are
    /// rejected, as required for untrusted data (wire, DHT, chain).
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let Ok(sig) = ed25519_dalek::Signature::from_slice(&signature.0) else {
            return false;
        };
        vk.verify_strict(payload, &sig).is_ok()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicKey(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Lowercase hex, 64 chars — consistent with `DomainId` output.
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// An Ed25519 signature (64 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Wraps 64 raw bytes.
    pub const fn from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signature(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A public key does not decode to a valid curve point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid Ed25519 public key")]
pub struct InvalidKeyError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate();
        let pk = sk.public_key();
        let sig = sk.sign(b"payload");
        assert!(pk.verify(b"payload", &sig));
        assert!(!pk.verify(b"other payload", &sig));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let sk = SigningKey::generate();
        let pk = sk.public_key();
        let mut raw = sk.sign(b"payload").to_bytes();
        raw[0] ^= 0x01;
        let bad = Signature::from_bytes(raw);
        assert!(!pk.verify(b"payload", &bad));
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let sk = SigningKey::generate();
        let pk = sk.public_key();
        let sig = sk.sign(b"original");
        assert!(!pk.verify(b"tampered", &sig));
    }

    #[test]
    fn key_bytes_roundtrip() {
        let sk = SigningKey::generate();
        let raw = sk.to_bytes();
        let restored = SigningKey::from_bytes(raw);
        assert_eq!(restored.to_bytes(), raw);
        assert_eq!(restored.public_key(), sk.public_key());
        // Same key ⇒ same signature.
        let msg = b"some canonical payload";
        assert_eq!(sk.sign(msg).to_bytes(), restored.sign(msg).to_bytes());
    }

    #[test]
    fn secret_key_never_leaks_in_debug() {
        let sk = SigningKey::generate();
        let dbg = format!("{sk:?}");
        let raw_hex: String = sk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert!(dbg.contains("<secret>"));
        assert!(!dbg.contains(&raw_hex));
    }

    #[test]
    fn debug_and_display_of_public_key_are_lowercase_hex() {
        let sk = SigningKey::generate();
        let display = sk.public_key().to_string();
        assert_eq!(display.len(), 64);
        assert!(
            display
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let dbg = format!("{:?}", sk.public_key());
        assert!(dbg.starts_with("PublicKey(") && dbg.ends_with(')'));
        assert!(dbg.contains(&display));
    }

    #[test]
    fn distinct_keys_sign_independently() {
        let a = SigningKey::generate();
        let b = SigningKey::generate();
        let msg = b"shared payload";
        let sa = a.sign(msg);
        let sb = b.sign(msg);
        assert_ne!(sa.to_bytes(), sb.to_bytes());
        assert!(a.public_key().verify(msg, &sa));
        assert!(!a.public_key().verify(msg, &sb));
    }

    #[test]
    fn invalid_public_key_bytes_are_rejected_without_panic() {
        // y = 2 is not a valid curve point encoding (not decompressable)
        // — must be an error, not a panic and not a silent accept.
        let mut not_on_curve = [0u8; PUBLIC_KEY_SIZE];
        not_on_curve[0] = 0x02;
        assert!(PublicKey::from_bytes(not_on_curve).is_err());
        // Sanity: the all-zero encoding (identity point, y = 0) is
        // accepted by `from_bytes`; `verify` (strict) is what rejects
        // weak keys at verification time.
        assert!(PublicKey::from_bytes([0x00; PUBLIC_KEY_SIZE]).is_ok());
    }

    // ---- RFC 8032 §7.1 official test vectors ----

    #[test]
    fn rfc8032_vector_1() {
        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let public: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let message: &[u8] = b"";
        let expected_sig: [u8; 64] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        let sk = SigningKey::from_bytes(secret);
        assert_eq!(sk.public_key().to_bytes(), public);
        let sig = sk.sign(message);
        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(PublicKey::from_bytes(public).unwrap().verify(message, &sig));
    }

    #[test]
    fn rfc8032_vector_2() {
        let secret: [u8; 32] = [
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11,
            0x4e, 0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed,
            0x4f, 0xb8, 0xa6, 0xfb,
        ];
        let public: [u8; 32] = [
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b,
            0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1,
            0x2a, 0xf4, 0x66, 0x0c,
        ];
        let message: &[u8] = b"\x72";
        let expected_sig: [u8; 64] = [
            0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64,
            0x25, 0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23,
            0xeb, 0xdb, 0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f,
            0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
            0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00,
        ];

        let sk = SigningKey::from_bytes(secret);
        assert_eq!(sk.public_key().to_bytes(), public);
        let sig = sk.sign(message);
        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(PublicKey::from_bytes(public).unwrap().verify(message, &sig));
    }

    #[test]
    fn rfc8032_vector_3() {
        let secret: [u8; 32] = [
            0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc,
            0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e,
            0x0b, 0x44, 0x58, 0xf7,
        ];
        let public: [u8; 32] = [
            0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30,
            0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15,
            0x48, 0x90, 0x80, 0x25,
        ];
        let message: &[u8] = b"\xaf\x82";
        let expected_sig: [u8; 64] = [
            0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe,
            0x01, 0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7,
            0xdb, 0x5a, 0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67,
            0xf7, 0x60, 0x98, 0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d,
            0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
        ];

        let sk = SigningKey::from_bytes(secret);
        assert_eq!(sk.public_key().to_bytes(), public);
        let sig = sk.sign(message);
        assert_eq!(sig.to_bytes(), expected_sig);
        assert!(PublicKey::from_bytes(public).unwrap().verify(message, &sig));
    }
}
