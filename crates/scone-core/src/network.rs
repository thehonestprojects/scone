//! Network identities and per-network protocol parameters (M8b).
//!
//! Scone runs distinct, disjoint networks — `scone-testnet` and
//! `scone-mainnet` — identified by a short canonical ASCII string, the
//! [`NetworkId`]. The network id is a domain-separation input in three
//! places (see `/docs/technical/blockchain.md`):
//!
//! - the **genesis hash**: the genesis block carries the network id in
//!   its `consensus` payload, so a testnet chain and a mainnet chain
//!   have different genesis hashes and no block ever crosses over
//!   (`UnknownParent`);
//! - the **transaction signing payload**: the network id is a signed
//!   field of every transaction, so a signature made for one network
//!   never verifies on another;
//! - the **registration PoW digest**: a proof mined for one network is
//!   not a proof on another.
//!
//! [`NetworkParams`] additionally makes the PoW difficulties per
//! network: symbolic on testnet (fast development), real on mainnet.
//! This crate holds only pure data — no I/O, no clock.

use crate::error::{Result, SconeError};

/// Maximum length of a network id (bytes).
pub const MAX_NETWORK_ID_LEN: usize = 16;

/// A canonical network identifier (e.g. `scone-testnet`).
///
/// 1..=16 bytes of ASCII `[a-z0-9-]`, never empty. [`NetworkId`] is
/// `Copy` (fixed inline buffer) so it can be threaded through every
/// transaction constructor without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkId {
    bytes: [u8; MAX_NETWORK_ID_LEN],
    len: u8,
}

impl NetworkId {
    /// The testnet identity (`scone-testnet`).
    pub const TESTNET: Self = Self::from_ascii(b"scone-testnet");
    /// The mainnet identity (`scone-mainnet`).
    pub const MAINNET: Self = Self::from_ascii(b"scone-mainnet");

    /// Builds a `NetworkId` from a compile-time-known ASCII literal.
    const fn from_ascii(literal: &[u8]) -> Self {
        let mut bytes = [0u8; MAX_NETWORK_ID_LEN];
        let mut i = 0;
        while i < literal.len() {
            bytes[i] = literal[i];
            i += 1;
        }
        Self {
            bytes,
            len: literal.len() as u8,
        }
    }

    /// Parses and validates a network id from untrusted input.
    ///
    /// # Errors
    ///
    /// [`SconeError::InvalidName`] when the id is empty, longer than
    /// [`MAX_NETWORK_ID_LEN`], or contains a byte outside
    /// `a-z`, `0-9`, `-`.
    pub fn new(input: &str) -> Result<Self> {
        let bytes = input.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NETWORK_ID_LEN {
            return Err(SconeError::InvalidName(format!(
                "network id must be 1..={MAX_NETWORK_ID_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        for &b in bytes {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
            if !ok {
                return Err(SconeError::InvalidName(format!(
                    "network id byte {b:#04x} is not in [a-z0-9-]"
                )));
            }
        }
        let mut out = [0u8; MAX_NETWORK_ID_LEN];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: out,
            len: bytes.len() as u8,
        })
    }

    /// The canonical ASCII bytes of the id.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(std::str::from_utf8(self.as_bytes()).unwrap_or("?"))
    }
}

/// Per-network protocol parameters (M8b).
///
/// PoW difficulties are network policy, not global constants: testnet
/// is deliberately symbolic so a proof mines in milliseconds, mainnet
/// carries the real economic weights. Changing any field is a
/// consensus change for that network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkParams {
    /// Identity of the network (genesis, signatures, PoW separation).
    pub network_id: NetworkId,
    /// Difficulty (leading zero bits) to claim a TLD.
    pub tld_pow_difficulty: u32,
    /// Difficulty (leading zero bits) to register a domain under an
    /// open TLD.
    pub domain_pow_difficulty: u32,
    /// PoS consensus parameters (committee, epochs, recovery) — the
    /// block-production authority and checkpoint finality. Ported
    /// from the .bak (M3 of the port).
    pub consensus: crate::consensus_params::ConsensusParams,
}

/// Testnet parameters: symbolic difficulties (M8b).
pub const TESTNET: NetworkParams = NetworkParams {
    consensus: crate::consensus_params::ConsensusParams::TESTNET,
    network_id: NetworkId::TESTNET,
    tld_pow_difficulty: 8,
    domain_pow_difficulty: 4,
};

/// Mainnet parameters: real difficulties (M8b).
pub const MAINNET: NetworkParams = NetworkParams {
    consensus: crate::consensus_params::ConsensusParams::PRODUCTION,
    network_id: NetworkId::MAINNET,
    tld_pow_difficulty: 24,
    domain_pow_difficulty: 20,
};

impl NetworkParams {
    /// Looks up the built-in network named `testnet` / `mainnet`.
    #[must_use]
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "testnet" => Some(TESTNET),
            "mainnet" => Some(MAINNET),
            _ => None,
        }
    }

    /// The short directory name of the network (`testnet`/`mainnet`).
    #[must_use]
    pub fn dir_name(&self) -> &'static str {
        if self.network_id == NetworkId::MAINNET {
            "mainnet"
        } else {
            "testnet"
        }
    }
}

// Compile-time sanity: difficulties are ordered as documented (a
// namespace claim costs more than a name claim, on both networks).
const _: () = assert!(TESTNET.tld_pow_difficulty > TESTNET.domain_pow_difficulty);
const _: () = assert!(MAINNET.tld_pow_difficulty > MAINNET.domain_pow_difficulty);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ids_roundtrip() {
        assert_eq!(NetworkId::TESTNET.to_string(), "scone-testnet");
        assert_eq!(NetworkId::MAINNET.to_string(), "scone-mainnet");
        assert_eq!(NetworkId::new("scone-testnet").unwrap(), NetworkId::TESTNET);
        assert_eq!(NetworkId::new("scone-mainnet").unwrap(), NetworkId::MAINNET);
    }

    #[test]
    fn rejects_bad_ids() {
        assert!(NetworkId::new("").is_err());
        assert!(NetworkId::new("Scone-Testnet").is_err());
        assert!(NetworkId::new("scone testnet").is_err());
        assert!(NetworkId::new("scone_testnet").is_err());
        assert!(NetworkId::new("an-id-way-too-long-for-the-buffer").is_err());
        assert!(NetworkId::new("u").is_ok());
    }

    #[test]
    fn params_are_distinct_and_ordered() {
        assert_ne!(TESTNET, MAINNET);
        assert_ne!(TESTNET.network_id, MAINNET.network_id);
        // Testnet stays symbolic: 8/4 bits mine in a few hundred
        // hashes at most (p = 2^-8 per draw ⇒ P(>256 draws) ≈ 37%,
        // P(>4096 draws) ≈ 1e-7 — effectively instant).
        assert_eq!(TESTNET.tld_pow_difficulty, 8);
        assert_eq!(TESTNET.domain_pow_difficulty, 4);
        assert_eq!(MAINNET.tld_pow_difficulty, 24);
        assert_eq!(MAINNET.domain_pow_difficulty, 20);
    }

    #[test]
    fn by_name_and_dir_name() {
        assert_eq!(NetworkParams::by_name("testnet"), Some(TESTNET));
        assert_eq!(NetworkParams::by_name("mainnet"), Some(MAINNET));
        assert_eq!(NetworkParams::by_name("regtest"), None);
        assert_eq!(TESTNET.dir_name(), "testnet");
        assert_eq!(MAINNET.dir_name(), "mainnet");
    }
}
