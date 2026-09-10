//! Owner identity.

/// Domain-separation prefix for [`PublicKeyRef`] computation.
pub const PUBKEY_REF_VERSION: &[u8] = b"SCONE-PUBKEY-V1";

/// Domain-separation prefix for [`OwnerId`] computation.
pub const OWNER_ID_VERSION: &[u8] = b"SCONE-OWNER-V1";

/// Opaque reference to an owner public key.
///
/// BLAKE3-256 of an encoded public key. The concrete key type (e.g.
/// Ed25519) lives in `scone-crypto`; `scone-core` never handles keys or
/// private key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyRef([u8; 32]);

impl PublicKeyRef {
    /// Deterministic reference to `encoded_public_key`.
    pub fn from_public_key(encoded_public_key: &[u8]) -> Self {
        Self(scone_crypto::hash256(&[
            PUBKEY_REF_VERSION,
            encoded_public_key,
        ]))
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Logical identity of a domain owner.
///
/// Derived from a [`PublicKeyRef`]; no private key material ever enters
/// `scone-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OwnerId([u8; 32]);

impl OwnerId {
    /// Identity bound to a public key reference.
    pub fn from_public_key_ref(public_key: &PublicKeyRef) -> Self {
        Self(scone_crypto::hash256(&[
            OWNER_ID_VERSION,
            public_key.as_bytes(),
        ]))
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_ref_is_deterministic() {
        assert_eq!(
            PublicKeyRef::from_public_key(b"ed25519-key-material"),
            PublicKeyRef::from_public_key(b"ed25519-key-material")
        );
    }

    #[test]
    fn distinct_keys_give_distinct_refs() {
        assert_ne!(
            PublicKeyRef::from_public_key(b"key-1"),
            PublicKeyRef::from_public_key(b"key-2")
        );
    }

    #[test]
    fn owner_id_is_deterministic_and_bound_to_key() {
        let pk1 = PublicKeyRef::from_public_key(b"key-1");
        let pk2 = PublicKeyRef::from_public_key(b"key-2");
        assert_eq!(
            OwnerId::from_public_key_ref(&pk1),
            OwnerId::from_public_key_ref(&pk1)
        );
        assert_ne!(
            OwnerId::from_public_key_ref(&pk1),
            OwnerId::from_public_key_ref(&pk2)
        );
    }

    #[test]
    fn owner_id_differs_from_public_key_ref() {
        let pk = PublicKeyRef::from_public_key(b"key-1");
        let owner = OwnerId::from_public_key_ref(&pk);
        assert_ne!(owner.as_bytes(), pk.as_bytes());
    }

    #[test]
    fn bytes_roundtrip() {
        let pk = PublicKeyRef::from_public_key(b"key-1");
        let owner = OwnerId::from_public_key_ref(&pk);
        assert_eq!(PublicKeyRef::from_bytes(*pk.as_bytes()), pk);
        assert_eq!(OwnerId::from_bytes(*owner.as_bytes()), owner);
    }
}
