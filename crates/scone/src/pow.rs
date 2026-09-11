//! Registration proof-of-work mining for the CLI (M8b).
//!
//! Verification stays in `scone-core` (`pow::verify`); this module is
//! the wallet-side search loop. On testnet the difficulties are
//! symbolic (8/4 bits): a proof mines in milliseconds. On mainnet
//! (24/20 bits) a claim takes real work — that is the point.

use scone_core::{NetworkParams, Proof};

/// Mines a domain registration proof at `network`'s difficulty.
pub(crate) fn mine_domain_proof(network: NetworkParams, name: &str) -> Proof {
    let mut challenge = Vec::with_capacity(scone_core::id::DOMAIN_ID_VERSION.len() + name.len());
    challenge.extend_from_slice(scone_core::id::DOMAIN_ID_VERSION);
    challenge.extend_from_slice(name.as_bytes());
    mine(network, challenge, network.domain_pow_difficulty)
}

/// Mines a TLD registration proof at `network`'s difficulty.
pub(crate) fn mine_tld_proof(network: NetworkParams, tld: &str) -> Proof {
    let mut challenge = Vec::with_capacity(scone_core::id::TLD_ID_VERSION.len() + tld.len());
    challenge.extend_from_slice(scone_core::id::TLD_ID_VERSION);
    challenge.extend_from_slice(tld.as_bytes());
    mine(network, challenge, network.tld_pow_difficulty)
}

fn mine(network: NetworkParams, challenge: Vec<u8>, difficulty: u32) -> Proof {
    let checked = scone_core::pow::mine(network.network_id, &challenge, difficulty);
    Proof::from_bytes(scone_core::pow::encode_proof(&checked))
}
