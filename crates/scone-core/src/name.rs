//! Strongly-typed domain names.

use std::fmt;

use crate::error::{Result, SconeError};

/// A top-level domain (TLD): `[a-z0-9-]{1,63}` (LDH: no leading/trailing
/// hyphen).
///
/// Validation is strict: uppercase, unicode and the empty string
/// are rejected rather than silently canonicalized. The canonical form of a
/// valid TLD is the string itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TldName(String);

impl TldName {
    /// Maximum TLD length in bytes (RFC 1035 label limit: a TLD is a
    /// DNS label like any other).
    pub const MAX_LEN: usize = 63;

    /// Parses and validates a TLD.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidTld`] if the input is empty, longer
    /// than [`MAX_LEN`](Self::MAX_LEN), or is not a valid LDH label.
    pub fn new(tld: &str) -> Result<Self> {
        Self::validate(tld)?;
        Ok(Self(tld.to_owned()))
    }

    /// Canonical form; by construction identical to the parsed input.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(tld: &str) -> Result<()> {
        if tld.is_empty() || tld.len() > Self::MAX_LEN {
            return Err(SconeError::InvalidTld(format!(
                "length must be 1..={}, got {}",
                Self::MAX_LEN,
                tld.len()
            )));
        }
        if !is_ldh(tld) {
            return Err(SconeError::InvalidTld(format!(
                "only LDH ([a-z0-9-], no leading/trailing hyphen) allowed, got {tld:?}"
            )));
        }
        Ok(())
    }
}

/// LDH rule (RFC 1123): `[a-z0-9-]`, hyphen neither first nor last byte.
fn is_ldh(label: &str) -> bool {
    !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl TryFrom<&str> for TldName {
    type Error = SconeError;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl fmt::Display for TldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A full domain name: one or more labels followed by a TLD,
/// dot-separated (`name.tld`, `shop.example.uip`).
///
/// Rules (see `/docs/general/naming.md`):
///
/// - LDH labels (`[a-z0-9-]`, hyphen neither first nor last byte)
/// - each label: 1..=63 bytes
/// - at least 2 labels (a bare TLD is not a [`DomainName`])
/// - total length <= 253 bytes
///
/// Validation is strict (no silent lowercasing); the canonical form of a
/// valid name is the name itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// Maximum label length in bytes.
    pub const MAX_LABEL_LEN: usize = 63;
    /// Maximum total length in bytes.
    pub const MAX_TOTAL_LEN: usize = 253;

    /// Parses and validates a domain name.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidDomain`] (or
    /// [`SconeError::InvalidTld`] for a malformed last label) if the input
    /// violates the naming rules.
    pub fn new(name: &str) -> Result<Self> {
        Self::validate(name)?;
        Ok(Self(name.to_owned()))
    }

    /// Canonical (wire/storage) form, identical to the parsed input.
    pub fn canonical(&self) -> &str {
        &self.0
    }

    /// Alias of [`canonical`](Self::canonical).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Labels in written order, most specific first.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// Number of labels (always >= 2).
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// The TLD (last label); valid by construction.
    pub fn tld(&self) -> TldName {
        let (_, tld) = self
            .0
            .rsplit_once('.')
            .expect("validated: at least one dot");
        TldName(tld.to_owned())
    }

    fn validate(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(SconeError::InvalidDomain("empty domain name".into()));
        }
        if name.len() > Self::MAX_TOTAL_LEN {
            return Err(SconeError::InvalidDomain(format!(
                "total length {} exceeds {}",
                name.len(),
                Self::MAX_TOTAL_LEN
            )));
        }
        let all = name.split('.').collect::<Vec<_>>();
        let (tld, labels) = all.split_last().expect("non-empty");
        if labels.is_empty() {
            return Err(SconeError::InvalidDomain(
                "at least two labels required (name.tld)".into(),
            ));
        }
        TldName::validate(tld)?;
        for (i, label) in labels.iter().enumerate() {
            if label.is_empty() {
                return Err(SconeError::InvalidDomain(format!(
                    "empty label at position {i}"
                )));
            }
            if label.len() > Self::MAX_LABEL_LEN {
                return Err(SconeError::InvalidDomain(format!(
                    "label longer than {} bytes",
                    Self::MAX_LABEL_LEN
                )));
            }
            if !is_ldh(label) {
                return Err(SconeError::InvalidDomain(format!(
                    "invalid characters in label {label:?}: only LDH ([a-z0-9-], no leading/trailing hyphen) allowed"
                )));
            }
        }
        Ok(())
    }
}

impl TryFrom<&str> for DomainName {
    type Error = SconeError;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_valid() {
        for tld in [
            "uip",
            "com",
            "test",
            "abc12",
            "0x",
            "a",
            "abcde",
            "a-b",
            "x-9",
            "abcdefghij", // 10 chars, was invalid at the old 5-byte limit
        ] {
            assert!(TldName::new(tld).is_ok(), "{tld} should be valid");
        }
    }

    #[test]
    fn tld_invalid() {
        for tld in [
            "",    // empty
            "ABC", // uppercase
            "Ab",  // mixed case
            "-ab", // leading hyphen
            "ab-", // trailing hyphen
            "-",   // hyphen only
            "a b", "éxemple", "a.b",
        ] {
            assert!(TldName::new(tld).is_err(), "{tld:?} should be invalid");
        }
    }

    #[test]
    fn tld_length_boundaries() {
        // A TLD is a DNS label (RFC 1035): 1..=63 bytes.
        assert_eq!(TldName::MAX_LEN, 63);
        assert!(TldName::new("a").is_ok());
        assert!(TldName::new(&"a".repeat(5)).is_ok()); // old upper bound, still valid
        assert!(TldName::new(&"a".repeat(63)).is_ok());
        assert!(TldName::new(&"a".repeat(64)).is_err());
        // Multi-byte characters count as bytes, not chars.
        assert!(TldName::new(&"é".repeat(32)).is_err()); // 64 bytes, 32 chars
    }

    #[test]
    fn tld_try_from_str() {
        assert!(TldName::try_from("uip").is_ok());
        assert!(TldName::try_from("ABC").is_err());
    }

    #[test]
    fn domain_valid() {
        for name in [
            "example.uip",
            "shop.example.uip",
            "api.shop.example.uip",
            "a.b",
            "0.0",
            "a1b2.uip",
            "x.y.z.w.uip",
            "foo-bar.uip",
            "foo--bar.uip",
            "a-b.example.x-9",
        ] {
            assert!(DomainName::new(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn domain_invalid() {
        for name in [
            "",             // empty
            "uip",          // single label (TLD only)
            ".uip",         // leading dot
            "example.",     // trailing dot
            "example..uip", // empty label
            "EXAMPLE.uip",  // uppercase
            "example.UIP",  // uppercase TLD
            "ex ample.uip", // space
            "-foo.uip",     // leading hyphen
            "foo-.uip",     // trailing hyphen
            "éxemple.uip",  // unicode
        ] {
            assert!(DomainName::new(name).is_err(), "{name:?} should be invalid");
        }
    }

    #[test]
    fn domain_label_length_boundaries() {
        let ok = format!("{}.uip", "a".repeat(63));
        let ko = format!("{}.uip", "a".repeat(64));
        assert!(DomainName::new(&ok).is_ok());
        assert!(DomainName::new(&ko).is_err());
    }

    #[test]
    fn domain_total_length_boundaries() {
        // 4 labels of 61 bytes + 4 dots + 5-byte TLD = 253 bytes exactly.
        let ok = format!(
            "{}.{}.{}.{}.abcde",
            "a".repeat(61),
            "b".repeat(61),
            "c".repeat(61),
            "d".repeat(61)
        );
        assert_eq!(ok.len(), 253);
        let ko = format!(
            "{}.{}.{}.{}.abcde",
            "a".repeat(62),
            "b".repeat(61),
            "c".repeat(61),
            "d".repeat(61)
        );
        assert!(DomainName::new(&ok).is_ok());
        assert!(DomainName::new(&ko).is_err());
    }

    #[test]
    fn long_tld_inside_domain_is_invalid_tld() {
        assert!(matches!(
            DomainName::new(&format!("example.{}", "a".repeat(64))),
            Err(SconeError::InvalidTld(_))
        ));
    }

    #[test]
    fn max_length_tld_inside_domain_is_valid() {
        let name = format!("example.{}", "a".repeat(63));
        let name = DomainName::new(&name).unwrap();
        assert_eq!(name.tld(), TldName::new(&"a".repeat(63)).unwrap());
    }

    #[test]
    fn canonical_and_accessors() {
        let name = DomainName::new("api.shop.example.uip").unwrap();
        assert_eq!(name.canonical(), "api.shop.example.uip");
        assert_eq!(name.as_str(), "api.shop.example.uip");
        assert_eq!(name.to_string(), "api.shop.example.uip");
        assert_eq!(name.label_count(), 4);
        assert_eq!(
            name.labels().collect::<Vec<_>>(),
            ["api", "shop", "example", "uip"]
        );
        assert_eq!(name.tld(), TldName::new("uip").unwrap());
    }

    #[test]
    fn canonical_form_is_stable() {
        // Strict validation: a valid name is already canonical.
        let a = DomainName::new("example.uip").unwrap();
        let b = DomainName::new("example.uip").unwrap();
        assert_eq!(a.canonical(), b.canonical());
        assert_eq!(a, b);
    }

    #[test]
    fn names_hash_consistently() {
        let mut set = std::collections::HashSet::new();
        set.insert(DomainName::new("example.uip").unwrap());
        assert!(set.contains(&DomainName::new("example.uip").unwrap()));
        assert!(!set.contains(&DomainName::new("other.uip").unwrap()));
    }
}
