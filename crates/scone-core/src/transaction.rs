//! Blockchain transactions.

use crate::error::{Result, SconeError};
use crate::id::DomainId;
use crate::owner::OwnerId;

/// Opaque registration proof (reserved for the future proof of work).
///
/// Not implemented yet: `Register` validation ignores its content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Proof(Vec<u8>);

impl Proof {
    /// Wraps raw proof bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Commitment to the full DNS record set of a domain.
///
/// Will be computed as
/// `BLAKE3-256("SCONE-RECORD-V1" || canonical_record_encoding)` once the
/// canonical encoding is defined by `scone-protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordHash([u8; 32]);

impl RecordHash {
    /// Raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Claims ownership of a domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Register {
    pub domain_id: DomainId,
    pub owner: OwnerId,
    /// Ordering information (Unix timestamp now; chain position later).
    pub timestamp: u64,
    /// Reserved for the registration proof of work (not yet implemented).
    pub proof: Proof,
}

/// Publishes a new version of a domain's DNS data.
///
/// On-chain: `domain_id + owner + sequence + record_hash`.
/// In the DHT: the full [`SignedDnsRecord`](crate::record::SignedDnsRecord)
/// whose hash must equal `record_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Update {
    pub domain_id: DomainId,
    pub owner: OwnerId,
    /// Monotonic version of the record set.
    pub sequence: u64,
    /// Commitment to the full DNS record set in the DHT.
    pub record_hash: RecordHash,
    /// Ordering information.
    pub timestamp: u64,
}

impl Update {
    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidSequence`] if `sequence` is `0`.
    pub fn validate(&self) -> Result<()> {
        if self.sequence == 0 {
            return Err(SconeError::InvalidSequence(0));
        }
        Ok(())
    }
}

/// A blockchain transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Transaction {
    /// See [`Register`].
    Register(Register),
    /// See [`Update`].
    Update(Update),
}

impl Transaction {
    /// The domain this transaction applies to.
    pub fn domain_id(&self) -> DomainId {
        match self {
            Self::Register(tx) => tx.domain_id,
            Self::Update(tx) => tx.domain_id,
        }
    }

    /// The declared owner.
    pub fn owner(&self) -> OwnerId {
        match self {
            Self::Register(tx) => tx.owner,
            Self::Update(tx) => tx.owner,
        }
    }

    /// Checks protocol invariants.
    ///
    /// # Errors
    ///
    /// Returns [`SconeError::InvalidSequence`] for an `Update` with a zero
    /// sequence. `Register` rules are not defined yet (proof of work to
    /// come) and always pass for now.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Register(_) => Ok(()),
            Self::Update(tx) => tx.validate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::DomainName;

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    fn register() -> Register {
        Register {
            domain_id: domain_id(),
            owner: OwnerId::from_bytes([1; 32]),
            timestamp: 1_700_000_000,
            proof: Proof::from_bytes(Vec::new()),
        }
    }

    fn update() -> Update {
        Update {
            domain_id: domain_id(),
            owner: OwnerId::from_bytes([1; 32]),
            sequence: 1,
            record_hash: RecordHash::from_bytes([9; 32]),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn register_validates_without_proof_of_work() {
        assert!(Transaction::Register(register()).validate().is_ok());
    }

    #[test]
    fn update_validates() {
        assert!(Transaction::Update(update()).validate().is_ok());
    }

    #[test]
    fn update_zero_sequence_is_invalid() {
        let mut tx = update();
        tx.sequence = 0;
        assert!(matches!(tx.validate(), Err(SconeError::InvalidSequence(0))));
        assert!(matches!(
            Transaction::Update(tx).validate(),
            Err(SconeError::InvalidSequence(0))
        ));
    }

    #[test]
    fn transaction_accessors() {
        let owner = OwnerId::from_bytes([1; 32]);
        assert_eq!(Transaction::Register(register()).domain_id(), domain_id());
        assert_eq!(Transaction::Update(update()).domain_id(), domain_id());
        assert_eq!(Transaction::Register(register()).owner(), owner);
        assert_eq!(Transaction::Update(update()).owner(), owner);
    }
}
