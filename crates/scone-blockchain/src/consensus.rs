//! Minimal consensus abstraction.
//!
//! The concrete consensus (PoW/RandomX, difficulty, fork choice,
//! timestamp/anti-replay rules, mempool admission) is a future
//! dedicated step. Until then, any implementation of [`Consensus`] can
//! be plugged into chain validation
//! ([`Blockchain::with_consensus`](crate::Blockchain::with_consensus));
//! [`PermissiveConsensus`] accepts everything and is the default.
//!
//! Voluntarily out of scope here: block production, difficulty targets,
//! chain selection between competing tips.

use scone_core::Transaction;
use scone_protocol::BlockHeader;

use crate::error::Result;

/// Consensus validation hooks, called by
/// [`Blockchain::push_block`](crate::Blockchain::push_block).
///
/// A future implementation checks here, among others: proof-of-work
/// validity, difficulty, registration proofs (the `proof` field of
/// `RegisterDomain`), fees/anti-spam, timestamp rules.
pub trait Consensus {
    /// Validates the consensus fields of a block header.
    ///
    /// # Errors
    ///
    /// Implementation-defined; see
    /// [`BlockchainError::Consensus`](crate::BlockchainError::Consensus).
    fn validate_header(&self, header: &BlockHeader) -> Result<()>;

    /// Validates the consensus aspects of a transaction (e.g. a
    /// `RegisterDomain` proof of work).
    ///
    /// # Errors
    ///
    /// Implementation-defined; see
    /// [`BlockchainError::Consensus`](crate::BlockchainError::Consensus).
    fn validate_tx(&self, tx: &Transaction) -> Result<()>;
}

/// Placeholder consensus: accepts everything.
///
/// Used until the real consensus rules are defined; it is the default
/// of [`Blockchain`](crate::Blockchain).
#[derive(Debug, Clone, Copy, Default)]
pub struct PermissiveConsensus;

impl Consensus for PermissiveConsensus {
    fn validate_header(&self, _header: &BlockHeader) -> Result<()> {
        Ok(())
    }

    fn validate_tx(&self, _tx: &Transaction) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_protocol::MerkleRoot;

    #[test]
    fn permissive_accepts_everything() {
        let header = BlockHeader {
            version: 1,
            height: 0,
            prev_hash: scone_protocol::BlockHash::from_bytes([0; 32]),
            tx_root: MerkleRoot::from_bytes([0; 32]),
            timestamp: 0,
            consensus: Vec::new(),
        };
        assert!(PermissiveConsensus.validate_header(&header).is_ok());

        let sk = scone_crypto::SigningKey::from_bytes([2u8; 32]);
        let tx = scone_core::Transaction::RegisterDomain(
            scone_core::RegisterDomain::register_domain_signed(
                scone_core::DomainName::new("example.uip").unwrap(),
                0,
                scone_core::Proof::from_bytes(Vec::new()),
                sk.public_key(),
                sk.sign(b"t"),
            ),
        );
        assert!(PermissiveConsensus.validate_tx(&tx).is_ok());
    }
}
