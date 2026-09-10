//! Domain identity.

use crate::name::DomainName;

/// Domain-separation prefix for [`DomainId`] computation.
pub const DOMAIN_ID_VERSION: &[u8] = b"SCONE-DOMAIN-V1";

/// Deterministic 32-byte identifier of a domain.
///
/// Computed as:
///
/// ```text
/// DomainId = BLAKE3-256("SCONE-DOMAIN-V1" || canonical_domain_name)
/// ```
///
/// (via [`scone_crypto::hash256`]; see `/docs/naming.md`).
///
/// This is the primary internal identifier used by the future blockchain
/// and DHT. Raw domain names must never be used as map/storage keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId([u8; 32]);

impl DomainId {
    /// Computes the deterministic id of `name`.
    pub fn from_name(name: &DomainName) -> Self {
        Self(scone_crypto::hash256(&[
            DOMAIN_ID_VERSION,
            name.canonical().as_bytes(),
        ]))
    }

    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes (decoded from storage or the wire).
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for DomainId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> DomainName {
        DomainName::new(s).unwrap()
    }

    #[test]
    fn same_canonical_name_gives_same_domain_id() {
        let a = DomainId::from_name(&name("example.uip"));
        let b = DomainId::from_name(&name("example.uip"));
        assert_eq!(a, b);
    }

    #[test]
    fn different_domains_give_different_domain_ids() {
        let a = DomainId::from_name(&name("example.uip"));
        let b = DomainId::from_name(&name("other.uip"));
        let c = DomainId::from_name(&name("example.com"));
        let d = DomainId::from_name(&name("shop.example.uip"));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        // A subdomain is a distinct identity from its parent.
        assert_ne!(a, d);
    }

    #[test]
    fn domain_id_is_deterministic_across_calls() {
        let a = DomainId::from_name(&name("example.uip"));
        let b = DomainId::from_name(&name("example.uip"));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn bytes_roundtrip() {
        let id = DomainId::from_name(&name("example.uip"));
        assert_eq!(DomainId::from_bytes(*id.as_bytes()), id);
        assert_eq!(DomainId::from(*id.as_bytes()), id);
    }

    #[test]
    fn usable_as_map_key() {
        let mut map = std::collections::HashMap::new();
        map.insert(DomainId::from_name(&name("example.uip")), 1u8);
        assert_eq!(map[&DomainId::from_name(&name("example.uip"))], 1);
        assert!(!map.contains_key(&DomainId::from_name(&name("other.uip"))));
    }
}
