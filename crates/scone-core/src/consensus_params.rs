//! PoS committee parameters (ported from scone.bak, M3 of the
//! .bak integration). These extend [`NetworkParams`]: the consensus
//! layer (block production authority + checkpoint finality) reads
//! them; the registration PoW difficulties stay separate.
//!
//! Semantics preserved from the .bak (`crates/common/src/config.rs`):
//!
//! - `committee_size` = 31 anchors, quorum `floor(2n/3)+1` = 21 (BFT
//!   intersection of quorums);
//! - `epoch_secs` = consensus-time delay before a recovery draw k
//!   becomes an allowed producer set extension (deterministic at
//!   replay — consensus time, never the local clock);
//! - `recovery_max_epochs` = maximum recovery counter;
//! - `epoch_min_blocks` = minimum blocks between two checkpoints.
//!
//! A committee smaller than [`MIN_FINALITY_COMMITTEE_SIZE`] never
//! claims BFT finality (quorum = n, one Byzantine member controls or
//! blocks it) — production stays allowed (bootstrap), finality is
//! deferred.

/// Minimum elected-committee size for BFT finality (n ≥ 3f+1, f=1).
pub const MIN_FINALITY_COMMITTEE_SIZE: usize = 4;

/// BFT quorum for an elected committee of `n`: floor(2n/3) + 1.
/// Always computed on the ELECTED size, never on responses received
/// (the quorum does not follow disappearances).
#[must_use]
pub const fn quorum_for(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// PoS consensus parameters (per network).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusParams {
    /// Elected committee size (anchors). Quorum is derived, never
    /// configured separately.
    pub committee_size: usize,
    /// Consensus-time delay before recovery draw k unlocks (seconds).
    pub epoch_secs: u64,
    /// Maximum recovery counter (k ≥ 1 = k-th recovery draw).
    pub recovery_max_epochs: u32,
    /// Minimum blocks between two checkpoints.
    pub epoch_min_blocks: u64,
}

impl ConsensusParams {
    /// Production values (ported verbatim from the .bak).
    pub const PRODUCTION: Self = Self {
        committee_size: 31,
        epoch_secs: 60,
        recovery_max_epochs: 3,
        epoch_min_blocks: 10,
    };

    /// Devnet/testnet values: small committee (finality deferred
    /// below [`MIN_FINALITY_COMMITTEE_SIZE`] would be meaningless, so
    /// keep 4 = the minimum BFT size), fast epochs.
    pub const TESTNET: Self = Self {
        committee_size: 4,
        epoch_secs: 10,
        recovery_max_epochs: 3,
        epoch_min_blocks: 4,
    };
}

const _: () = {
    assert!(ConsensusParams::PRODUCTION.committee_size >= MIN_FINALITY_COMMITTEE_SIZE);
    assert!(quorum_for(31) == 21);
    assert!(quorum_for(4) == 3);
    // A committee below the BFT floor must require unanimity (the
    // formula yields n) — finality is then explicitly NOT Byzantine
    // safe, which the finality layer refuses to claim.
    assert!(quorum_for(3) == 3);
    assert!(quorum_for(2) == 2);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_is_two_thirds_floor_plus_one() {
        assert_eq!(quorum_for(31), 21);
        assert_eq!(quorum_for(30), 21);
        assert_eq!(quorum_for(4), 3);
        assert_eq!(quorum_for(3), 3);
        assert_eq!(quorum_for(1), 1);
    }

    #[test]
    fn production_params_are_pinned() {
        let p = ConsensusParams::PRODUCTION;
        assert_eq!(p.committee_size, 31);
        assert_eq!(p.epoch_secs, 60);
        assert_eq!(p.recovery_max_epochs, 3);
        assert_eq!(p.epoch_min_blocks, 10);
    }
}
