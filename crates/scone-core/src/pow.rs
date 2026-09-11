//! Registration proof of work (M8a/M8b) — **pure verification** plus a
//! wallet-side search helper.
//!
//! A registration PoW binds a *network*, a *challenge* (the object
//! being claimed) and a nonce:
//!
//! ```text
//! digest = BLAKE3-256("SCONE-POW-V1" || network || challenge || nonce_le)
//! ```
//!
//! where `network` is the canonical [`NetworkId`] bytes (M8b network
//! separation: a proof mined for one network is not a proof on
//! another), `challenge` is the domain-separation-prefixed derivation
//! input of the claimed object (`"SCONE-TLD-V1" || tld` for a TLD,
//! `"SCONE-DOMAIN-V1" || name` for a domain — exactly the bytes
//! hashed by [`crate::id`], so a proof can never be replayed across
//! namespaces or object kinds) and `nonce_le` is the 8-byte
//! little-endian encoding of the nonce.
//!
//! The proof **validates** when `digest` has at least `difficulty`
//! leading zero bits. Difficulty is expressed in bits (0..=256) and
//! is a **per-network parameter**
//! ([`crate::network::NetworkParams`]): symbolic on testnet (8/4
//! bits), real on mainnet (24/20 bits). Claiming a whole namespace
//! always costs more than claiming one name inside it. Changing a
//! difficulty is a consensus change for that network (see
//! `/docs/technical/transactions.md`).
//!
//! Verification is pure, deterministic, allocation-free and
//! constant-time-ish (one BLAKE3 pass): safe to run on any untrusted
//! transaction payload. The state layer (M8b) calls [`verify`] when a
//! proof is required — `RegisterTld`, and `RegisterDomain` under an
//! open TLD.
//!
//! Layering: `scone-crypto` hashes, `scone-core` verifies the PoW.

use crate::error::{Result, SconeError};
use crate::network::NetworkId;

/// Domain-separation prefix of the registration proof of work.
pub const POW_VERSION: &[u8] = b"SCONE-POW-V1";

/// A checked proof of work (nonce + difficulty), cheap to re-verify.
///
/// Built from the raw fields carried by a `RegisterTld` /
/// `RegisterDomain` `proof` payload; see [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedPow {
    /// The verified nonce.
    pub nonce: u64,
    /// The difficulty that was verified (leading zero bits).
    pub difficulty: u32,
}

/// Computes the PoW digest of `challenge` and `nonce` on `network`.
///
/// `challenge` must already be domain-separated (the derivation
/// input of the claimed object — pass the exact bytes used for
/// `TldId` / `DomainId` derivation, never a bare name).
#[must_use]
pub fn digest(network: NetworkId, challenge: &[u8], nonce: u64) -> [u8; 32] {
    scone_crypto::hash256(&[
        POW_VERSION,
        network.as_bytes(),
        challenge,
        &nonce.to_le_bytes(),
    ])
}

/// Counts the leading zero bits of `digest` (0..=256).
#[must_use]
pub fn leading_zero_bits(digest: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for &byte in digest {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}

/// Verifies that `nonce` solves the PoW for `challenge` on `network`
/// at `difficulty`.
///
/// # Errors
///
/// Returns [`SconeError::InvalidProof`] when the digest has fewer
/// than `difficulty` leading zero bits, or when `difficulty > 256`.
pub fn check(
    network: NetworkId,
    challenge: &[u8],
    nonce: u64,
    difficulty: u32,
) -> Result<CheckedPow> {
    if difficulty > 256 {
        return Err(SconeError::InvalidProof(
            "difficulty exceeds 256 bits".into(),
        ));
    }
    let d = digest(network, challenge, nonce);
    let zeros = leading_zero_bits(&d);
    if zeros < difficulty {
        return Err(SconeError::InvalidProof(format!(
            "insufficient proof of work: {zeros} leading zero bits, {difficulty} required"
        )));
    }
    Ok(CheckedPow { nonce, difficulty })
}

/// Brute-forces a nonce until the PoW solves (wallet/CLI search).
///
/// Verification stays the authority; this is the only sanctioned
/// mining loop, used by the CLI `domain register` path and tests. On
/// testnet difficulties (8/4 bits) it returns after a few hundred
/// hashes at most.
#[must_use]
pub fn mine(network: NetworkId, challenge: &[u8], difficulty: u32) -> CheckedPow {
    let mut nonce = 0u64;
    loop {
        if let Ok(checked) = check(network, challenge, nonce, difficulty) {
            return checked;
        }
        nonce += 1;
    }
}

/// Serialises a verified [`CheckedPow`] into the opaque `proof`
/// payload of a registration transaction.
///
/// Layout (fixed, 12 bytes): `nonce_le[8] || difficulty_le[4]`. The
/// difficulty travels with the proof so the verifier can re-check it
/// against the network parameter rather than trusting the producer
/// (see [`verify`]).
#[must_use]
pub fn encode_proof(checked: &CheckedPow) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&checked.nonce.to_le_bytes());
    out.extend_from_slice(&checked.difficulty.to_le_bytes());
    out
}

/// Parses and re-verifies a `proof` payload produced by
/// [`encode_proof`], against the expected difficulty `expected`.
///
/// The payload carries a self-declared difficulty; it is **never
/// trusted**: `verify` rejects the proof unless that difficulty
/// equals `expected` — the network parameter for the registration
/// kind being verified (`tld_pow_difficulty` for `RegisterTld`,
/// `domain_pow_difficulty` for `RegisterDomain` under an open TLD).
/// A producer can neither lower the bar nor raise it.
///
/// # Errors
///
/// Returns [`SconeError::InvalidProof`] when the payload is not the
/// exact 12-byte layout, its self-declared difficulty differs from
/// `expected`, or the nonce does not solve the challenge at
/// `expected` difficulty (the digest is recomputed from scratch —
/// never trusted).
pub fn verify(
    network: NetworkId,
    challenge: &[u8],
    proof: &[u8],
    expected: u32,
) -> Result<CheckedPow> {
    if proof.len() != 12 {
        return Err(SconeError::InvalidProof(format!(
            "proof payload must be exactly 12 bytes, got {}",
            proof.len()
        )));
    }
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&proof[..8]);
    let mut difficulty_bytes = [0u8; 4];
    difficulty_bytes.copy_from_slice(&proof[8..]);
    let nonce = u64::from_le_bytes(nonce_bytes);
    let difficulty = u32::from_le_bytes(difficulty_bytes);
    // The difficulty field is producer-controlled: only an exact
    // match with the network parameter for this registration kind is
    // acceptable. Anything else — lower (cheapened work) or higher —
    // is a consensus violation.
    if difficulty != expected {
        return Err(SconeError::InvalidProof(format!(
            "self-declared difficulty {difficulty} does not match the network parameter {expected}"
        )));
    }
    // Full re-verification: a well-formed payload with a non-solving
    // nonce is still a failure.
    check(network, challenge, nonce, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{MAINNET, TESTNET};

    /// Brute-forces a nonce (test-only mining helper).
    fn mine_legacy(network: NetworkId, challenge: &[u8], difficulty: u32) -> u64 {
        let mut nonce = 0u64;
        while !check(network, challenge, nonce, difficulty).is_ok() {
            nonce += 1;
        }
        nonce
    }

    fn tld_challenge() -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(crate::id::TLD_ID_VERSION);
        c.extend_from_slice(b"uip");
        c
    }

    fn domain_challenge() -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(crate::id::DOMAIN_ID_VERSION);
        c.extend_from_slice(b"example.uip");
        c
    }

    #[test]
    fn digest_is_deterministic_and_nonce_sensitive() {
        let c = tld_challenge();
        let n = TESTNET.network_id;
        assert_eq!(digest(n, &c, 7), digest(n, &c, 7));
        assert_ne!(digest(n, &c, 7), digest(n, &c, 8));
        assert_ne!(digest(n, &c, 7), digest(MAINNET.network_id, &c, 7));
        assert_ne!(digest(n, &c, 7), digest(n, &domain_challenge(), 7));
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0; 32]), 256);
        assert_eq!(leading_zero_bits(&[0xff; 32]), 0);
        let mut lead = [0u8; 32];
        lead[0] = 0x80;
        assert_eq!(leading_zero_bits(&lead), 0);
        lead[0] = 0x40;
        assert_eq!(leading_zero_bits(&lead), 1);
        lead[0] = 0x01;
        assert_eq!(leading_zero_bits(&lead), 7);
        lead[0] = 0x00;
        lead[1] = 0x80;
        assert_eq!(leading_zero_bits(&lead), 8);
    }

    #[test]
    fn check_accepts_a_mined_nonce() {
        let c = tld_challenge();
        let nonce = mine_legacy(TESTNET.network_id, &c, 16);
        let checked = check(TESTNET.network_id, &c, nonce, 16).unwrap();
        assert_eq!(checked.nonce, nonce);
        assert_eq!(checked.difficulty, 16);
    }

    #[test]
    fn check_rejects_insufficient_work() {
        let c = tld_challenge();
        // nonce 0 is astronomically unlikely to solve 32 bits.
        assert!(matches!(
            check(TESTNET.network_id, &c, 0, 32),
            Err(SconeError::InvalidProof(_))
        ));
    }

    #[test]
    fn check_rejects_absurd_difficulty() {
        assert!(matches!(
            check(TESTNET.network_id, &tld_challenge(), 0, 257),
            Err(SconeError::InvalidProof(_))
        ));
    }

    #[test]
    fn proof_roundtrip_reverifies_from_scratch() {
        let c = domain_challenge();
        let nonce = mine_legacy(TESTNET.network_id, &c, TESTNET.domain_pow_difficulty);
        let checked = check(TESTNET.network_id, &c, nonce, TESTNET.domain_pow_difficulty).unwrap();
        let payload = encode_proof(&checked);
        assert_eq!(payload.len(), 12);
        assert_eq!(
            verify(
                TESTNET.network_id,
                &c,
                &payload,
                TESTNET.domain_pow_difficulty
            )
            .unwrap(),
            checked
        );
    }

    #[test]
    fn verify_rejects_wrong_length() {
        let c = domain_challenge();
        assert!(matches!(
            verify(TESTNET.network_id, &c, &[], TESTNET.domain_pow_difficulty),
            Err(SconeError::InvalidProof(_))
        ));
        assert!(matches!(
            verify(
                TESTNET.network_id,
                &c,
                &[0; 11],
                TESTNET.domain_pow_difficulty
            ),
            Err(SconeError::InvalidProof(_))
        ));
        assert!(matches!(
            verify(
                TESTNET.network_id,
                &c,
                &[0; 13],
                TESTNET.domain_pow_difficulty
            ),
            Err(SconeError::InvalidProof(_))
        ));
    }

    #[test]
    fn verify_rejects_well_formed_but_non_solving_payload() {
        let c = tld_challenge();
        // nonce 0 with an honest difficulty byte pattern: fails the
        // digest re-check, not the layout check.
        let payload = encode_proof(&CheckedPow {
            nonce: 0,
            difficulty: TESTNET.tld_pow_difficulty,
        });
        assert!(matches!(
            verify(TESTNET.network_id, &c, &payload, TESTNET.tld_pow_difficulty),
            Err(SconeError::InvalidProof(_))
        ));
    }

    #[test]
    fn verify_rejects_self_declared_difficulty_not_matching_network_parameter() {
        // Reviewer repro: the producer declares its own difficulty.
        // Lowered bar: any nonce "solves" difficulty 0, so a payload
        // with a self-declared low difficulty must NOT verify against
        // the network parameter for that registration kind.
        let c = domain_challenge();
        let payload = encode_proof(&CheckedPow {
            nonce: 0,
            difficulty: 0,
        });
        assert!(matches!(
            verify(
                TESTNET.network_id,
                &c,
                &payload,
                TESTNET.domain_pow_difficulty
            ),
            Err(SconeError::InvalidProof(_))
        ));

        // Raised bar is equally rejected: a payload declaring a HIGHER
        // difficulty than the parameter fails verification on the
        // parameter check alone (rejection precedes any digest work).
        let nonce = mine_legacy(TESTNET.network_id, &c, TESTNET.domain_pow_difficulty);
        let payload = encode_proof(&CheckedPow {
            nonce,
            difficulty: TESTNET.domain_pow_difficulty + 4,
        });
        assert!(matches!(
            verify(
                TESTNET.network_id,
                &c,
                &payload,
                TESTNET.domain_pow_difficulty
            ),
            Err(SconeError::InvalidProof(_))
        ));

        // Cross-kind confusion: a payload declaring the TLD difficulty
        // must not verify as a domain proof — the parameters differ,
        // so the parameter check alone rejects it.
        let tld_c = tld_challenge();
        let tld_payload = encode_proof(&CheckedPow {
            nonce: 0,
            difficulty: TESTNET.tld_pow_difficulty,
        });
        assert!(matches!(
            verify(
                TESTNET.network_id,
                &tld_c,
                &tld_payload,
                TESTNET.domain_pow_difficulty
            ),
            Err(SconeError::InvalidProof(_))
        ));
    }

    #[test]
    fn verify_rejects_payload_with_absurd_difficulty() {
        let c = tld_challenge();
        let mut payload = vec![0u8; 12];
        payload[8..].copy_from_slice(&257u32.to_le_bytes());
        assert!(matches!(
            verify(TESTNET.network_id, &c, &payload, TESTNET.tld_pow_difficulty),
            Err(SconeError::InvalidProof(_))
        ));
    }

    // --- M8b network separation ---

    #[test]
    fn a_testnet_proof_is_not_a_mainnet_proof() {
        // Same challenge, same nonce: the digest differs per network,
        // so a proof that verifies on testnet fails on mainnet even
        // at the (lower) testnet difficulty.
        let c = tld_challenge();
        let checked = mine(TESTNET.network_id, &c, TESTNET.tld_pow_difficulty);
        let payload = encode_proof(&checked);
        assert!(verify(TESTNET.network_id, &c, &payload, TESTNET.tld_pow_difficulty).is_ok());
        // Mainnet re-check at its own difficulty: fails (declared
        // difficulty mismatch at minimum).
        assert!(matches!(
            verify(MAINNET.network_id, &c, &payload, MAINNET.tld_pow_difficulty),
            Err(SconeError::InvalidProof(_))
        ));
        // Even re-declared honestly at the mainnet difficulty, the
        // testnet-mined nonce does not solve the mainnet digest.
        let redeclared = encode_proof(&CheckedPow {
            nonce: checked.nonce,
            difficulty: MAINNET.tld_pow_difficulty,
        });
        assert!(matches!(
            verify(
                MAINNET.network_id,
                &c,
                &redeclared,
                MAINNET.tld_pow_difficulty
            ),
            Err(SconeError::InvalidProof(_))
        ));
    }

    #[test]
    fn testnet_difficulties_are_symbolic() {
        // M8b acceptance: a testnet PoW mines in a few ms — the
        // search terminates within a small, deterministic-ish bound
        // (2^-8 per draw for a TLD: P(>4096 draws) < 1e-7).
        let c = tld_challenge();
        let checked = mine(TESTNET.network_id, &c, TESTNET.tld_pow_difficulty);
        assert!(checked.nonce < 4096, "testnet TLD PoW took {checked:?}");
        let c2 = domain_challenge();
        let checked2 = mine(TESTNET.network_id, &c2, TESTNET.domain_pow_difficulty);
        assert!(checked2.nonce < 512, "testnet domain PoW took {checked2:?}");
    }
}
