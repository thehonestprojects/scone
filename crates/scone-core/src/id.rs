//! Domain identity.

use crate::name::{DomainName, TldName};

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
/// (via [`scone_crypto::hash256`]; see `/docs/general/naming.md`).
///
/// This is the primary internal identifier used by the future blockchain
/// and DHT. Raw domain names must never be used as map/storage keys.
///
/// Textual representation ([`std::fmt::Display`] and [`std::fmt::Debug`]):
/// the full 32 raw bytes encoded as 64 lowercase hexadecimal characters
/// (`0-9a-f`), with no prefix and never truncated. `Debug` wraps the same
/// hex string in `DomainId(<hex>)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Full lowercase hex encoding of the 32 raw bytes (64 chars).
    fn to_hex(self) -> String {
        const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for &byte in self.0.iter() {
            out.push(HEX_TABLE[usize::from(byte >> 4)] as char);
            out.push(HEX_TABLE[usize::from(byte & 0x0f)] as char);
        }
        out
    }
}

impl std::fmt::Display for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for DomainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DomainId({})", self.to_hex())
    }
}

impl From<[u8; 32]> for DomainId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Domain-separation prefix for [`TldId`] computation.
///
/// Distinct from [`DOMAIN_ID_VERSION`]: a TLD and a hypothetical
/// single-label domain are different namespaces and must never share
/// an id space (a cross-namespace collision would let a TLD
/// registration squat a domain identity, or vice versa).
pub const TLD_ID_VERSION: &[u8] = b"SCONE-TLD-V1";

/// Deterministic 32-byte identifier of a top-level domain.
///
/// Computed as:
///
/// ```text
/// TldId = BLAKE3-256("SCONE-TLD-V1" || tld)
/// ```
///
/// (via [`scone_crypto::hash256`]; see `/docs/general/naming.md`).
///
/// Distinct by construction from the [`DomainId`] of any domain (the
/// derivation prefixes differ). Textual representation: 64 lowercase
/// hex characters, never truncated — same conventions as `DomainId`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TldId([u8; 32]);

impl TldId {
    /// Computes the deterministic id of `tld`.
    pub fn from_tld(tld: &TldName) -> Self {
        Self(scone_crypto::hash256(&[
            TLD_ID_VERSION,
            tld.as_str().as_bytes(),
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

    /// Full lowercase hex encoding of the 32 raw bytes (64 chars).
    fn to_hex(self) -> String {
        const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for &byte in self.0.iter() {
            out.push(HEX_TABLE[usize::from(byte >> 4)] as char);
            out.push(HEX_TABLE[usize::from(byte & 0x0f)] as char);
        }
        out
    }
}

impl std::fmt::Display for TldId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl std::fmt::Debug for TldId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TldId({})", self.to_hex())
    }
}

impl From<[u8; 32]> for TldId {
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

    #[test]
    fn display_is_full_lowercase_hex() {
        let id = DomainId::from_bytes([0xab; 32]);
        let s = id.to_string();
        assert_eq!(s, "ab".repeat(32));
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn debug_contains_the_same_hex() {
        let id = DomainId::from_bytes([0xab; 32]);
        let dbg = format!("{id:?}");
        assert!(dbg.contains(&id.to_string()));
        assert!(dbg.starts_with("DomainId("));
        assert!(dbg.ends_with(')'));
    }

    #[test]
    fn display_of_all_zero_bytes_is_64_zeroes() {
        let id = DomainId::from_bytes([0x00; 32]);
        assert_eq!(id.to_string(), "0".repeat(64));
    }

    // --- TldId ---

    fn tld(s: &str) -> TldName {
        TldName::new(s).unwrap()
    }

    #[test]
    fn same_tld_gives_same_tld_id() {
        assert_eq!(TldId::from_tld(&tld("uip")), TldId::from_tld(&tld("uip")));
    }

    #[test]
    fn different_tlds_give_different_tld_ids() {
        assert_ne!(TldId::from_tld(&tld("uip")), TldId::from_tld(&tld("com")));
        assert_ne!(TldId::from_tld(&tld("a")), TldId::from_tld(&tld("b")));
    }

    #[test]
    fn tld_id_is_deterministic_across_calls() {
        let a = TldId::from_tld(&tld("uip"));
        let b = TldId::from_tld(&tld("uip"));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn tld_id_prefix_is_distinct_from_domain_prefix() {
        // "préfixe distinct": TLD ids live in their own namespace.
        assert_ne!(TLD_ID_VERSION, DOMAIN_ID_VERSION);
    }

    #[test]
    fn tld_id_never_collides_with_a_domain_id() {
        // Even for overlapping strings, the distinct derivation prefix
        // keeps the id spaces disjoint.
        let tld_id = TldId::from_tld(&tld("uip"));
        let domain_id = DomainId::from_name(&name("example.uip"));
        assert_ne!(tld_id.as_bytes(), domain_id.as_bytes());
        // Cross-namespace check with a crafted same-suffix name.
        let other = DomainId::from_name(&name("uip.uip"));
        assert_ne!(tld_id.as_bytes(), other.as_bytes());
    }

    #[test]
    fn tld_id_bytes_roundtrip() {
        let id = TldId::from_tld(&tld("uip"));
        assert_eq!(TldId::from_bytes(*id.as_bytes()), id);
        assert_eq!(TldId::from(*id.as_bytes()), id);
    }

    #[test]
    fn tld_id_usable_as_map_key() {
        let mut map = std::collections::HashMap::new();
        map.insert(TldId::from_tld(&tld("uip")), 1u8);
        assert_eq!(map[&TldId::from_tld(&tld("uip"))], 1);
        assert!(!map.contains_key(&TldId::from_tld(&tld("com"))));
    }

    #[test]
    fn tld_id_display_is_full_lowercase_hex() {
        let id = TldId::from_bytes([0xcd; 32]);
        let s = id.to_string();
        assert_eq!(s, "cd".repeat(32));
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn tld_id_debug_contains_the_same_hex() {
        let id = TldId::from_bytes([0xcd; 32]);
        let dbg = format!("{id:?}");
        assert!(dbg.contains(&id.to_string()));
        assert!(dbg.starts_with("TldId("));
        assert!(dbg.ends_with(')'));
    }

    #[test]
    fn tld_id_known_answer() {
        // Pinned vector: BLAKE3-256("SCONE-TLD-V1" || "uip"). Any change
        // to the derivation (prefix, input layout) breaks this test
        // instead of silently renumbering every TLD id.
        let id = TldId::from_tld(&tld("uip"));
        assert_eq!(
            id.to_string(),
            "ad5a86d68643d5c22d6a959bb1a315530c77dfda241f1ac1a8107450f3fab25e"
        );
    }
}
