//! Block assembly from a queue of validated transactions.
//!
//! [`BlockBuilder`] computes everything from scratch — `tx_root` over
//! the ordered transaction list, header chaining on the parent hash —
//! and never trusts provided commitments. The consensus payload and
//! timestamp are supplied by the caller (the future consensus layer
//! owns PoW/difficulty rules); the [`Consensus`] trait is used by the
//! chain at validation time, symmetric with `push_block`.

use scone_protocol::limits::MAX_TXS_PER_BLOCK;
use scone_protocol::{Block, BlockHash, BlockHeader, PROTOCOL_VERSION};

use crate::block_hash::block_hash;
use crate::error::{BlockchainError, Result};
use crate::merkle::tx_root;

/// Assembles a block extending `prev_hash` at `parent_height + 1`.
#[derive(Debug, Clone)]
pub struct BlockBuilder {
    prev_hash: BlockHash,
    height: u64,
    timestamp: u64,
    consensus: Vec<u8>,
    transactions: Vec<scone_core::Transaction>,
}

impl BlockBuilder {
    /// New builder for height `parent_height + 1` extending
    /// `prev_hash` (use the canonical tip hash of the parent block).
    #[must_use]
    pub fn after(parent_height: u64, prev_hash: BlockHash) -> Self {
        Self {
            prev_hash,
            height: parent_height + 1,
            timestamp: 0,
            consensus: Vec::new(),
            transactions: Vec::new(),
        }
    }

    /// Sets the block timestamp (ordering information; Unix seconds).
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the opaque consensus payload (PoW fields, etc.).
    #[must_use]
    pub fn with_consensus(mut self, consensus: Vec<u8>) -> Self {
        self.consensus = consensus;
        self
    }

    /// Appends transactions to the queue, preserving order.
    ///
    /// # Errors
    ///
    /// Returns [`BlockchainError::TooManyTransactions`] beyond
    /// `MAX_TXS_PER_BLOCK`.
    pub fn push_tx(&mut self, tx: scone_core::Transaction) -> Result<()> {
        if self.transactions.len() >= MAX_TXS_PER_BLOCK {
            return Err(BlockchainError::TooManyTransactions(
                self.transactions.len() + 1,
            ));
        }
        self.transactions.push(tx);
        Ok(())
    }

    /// Number of queued transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether no transaction is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Assembles the final block: `tx_root` recomputed over the queued
    /// transactions in order, header chained on `prev_hash`.
    ///
    /// # Errors
    ///
    /// Returns a [`BlockchainError`] if a transaction or the header
    /// cannot be canonically encoded. Never panics.
    pub fn build(self) -> Result<Block> {
        let tx_root = tx_root(&self.transactions)?;
        let header = BlockHeader {
            version: PROTOCOL_VERSION,
            height: self.height,
            prev_hash: self.prev_hash,
            tx_root,
            timestamp: self.timestamp,
            consensus: self.consensus,
        };
        // Encoding check (version, consensus bounds…) before handing
        // the block out.
        block_hash(&header)?;
        Ok(Block {
            header,
            transactions: self.transactions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::genesis_hash;
    use scone_core::{
        DomainId, DomainName, Proof, RecordHash, RegisterDomain, Transaction, UpdateDomain,
    };
    use scone_crypto::{Signature, SigningKey};

    fn domain_id() -> DomainId {
        DomainId::from_name(&DomainName::new("example.uip").unwrap())
    }

    /// Signs a register over the canonical payload (test helper).
    fn signed_register_domain(sk: &SigningKey, name: &str) -> Transaction {
        sign(
            Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                Proof::from_bytes(Vec::new()),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    fn signed_update_domain(sk: &SigningKey, sequence: u64) -> Transaction {
        sign(
            Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
                domain_id(),
                sequence,
                RecordHash::from_bytes([sequence as u8; 32]),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    /// Replaces the placeholder signature with a real one over the
    /// canonical signing payload of the transaction.
    fn sign(unsigned: Transaction, sk: &SigningKey) -> Transaction {
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        match unsigned {
            Transaction::RegisterDomain(mut r) => {
                r.signature = sk.sign(&payload);
                Transaction::RegisterDomain(r)
            }
            Transaction::UpdateDomain(mut u) => {
                u.signature = sk.sign(&payload);
                Transaction::UpdateDomain(u)
            }
            Transaction::RegisterTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::RegisterTld(t)
            }
        }
    }

    /// Signs a TLD claim over the canonical payload (test helper, M7c:
    /// D1 requires the namespace on-chain before any domain under it).
    fn signed_register_tld(sk: &SigningKey, tld: &str) -> Transaction {
        sign(
            Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
                scone_core::TldId::from_tld(&scone_core::TldName::new(tld).unwrap()),
                1,
                Proof::from_bytes(Vec::new()),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    #[test]
    fn builds_on_genesis_with_recomputed_root() {
        let sk = SigningKey::from_bytes([1; 32]);
        let mut builder = BlockBuilder::after(0, genesis_hash()).with_timestamp(1_700_000_000);
        builder.push_tx(signed_register_tld(&sk, "uip")).unwrap();
        builder
            .push_tx(signed_register_domain(&sk, "example.uip"))
            .unwrap();
        let block = builder.build().unwrap();

        assert_eq!(block.header.version, PROTOCOL_VERSION);
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.prev_hash, genesis_hash());
        assert_eq!(block.header.timestamp, 1_700_000_000);
        // tx_root is the recomputed root, not a provided value.
        assert_eq!(block.header.tx_root, tx_root(&block.transactions).unwrap());
        // The chain accepts the assembled block as-is.
        let mut chain = crate::Blockchain::new();
        assert_eq!(
            chain.push_block(&block).unwrap(),
            block_hash(&block.header).unwrap()
        );
    }

    #[test]
    fn chaining_genesis_block1_block2() {
        let sk = SigningKey::from_bytes([1; 32]);
        let mut chain = crate::Blockchain::new();

        let b1 = {
            let mut b = BlockBuilder::after(chain.height(), chain.tip_hash()).with_timestamp(10);
            b.push_tx(signed_register_tld(&sk, "uip")).unwrap();
            b.push_tx(signed_register_domain(&sk, "example.uip"))
                .unwrap();
            b.build().unwrap()
        };
        chain.push_block(&b1).unwrap();

        let b2 = {
            let mut b = BlockBuilder::after(chain.height(), chain.tip_hash()).with_timestamp(20);
            b.push_tx(signed_update_domain(&sk, 1)).unwrap();
            b.build().unwrap()
        };
        chain.push_block(&b2).unwrap();

        assert_eq!(chain.height(), 2);
        let domain = chain.state().domain(&domain_id()).unwrap();
        assert_eq!(domain.sequence, 1);
        assert_eq!(domain.record_hash, Some(RecordHash::from_bytes([1; 32])));
    }

    #[test]
    fn deterministic_replay_same_bytes_same_chain() {
        let sk = SigningKey::from_bytes([1; 32]);
        let assemble = || {
            let mut chain = crate::Blockchain::new();
            let b1 = {
                let mut b =
                    BlockBuilder::after(chain.height(), chain.tip_hash()).with_timestamp(10);
                b.push_tx(signed_register_tld(&sk, "uip")).unwrap();
                b.push_tx(signed_register_domain(&sk, "example.uip"))
                    .unwrap();
                b.build().unwrap()
            };
            chain.push_block(&b1).unwrap();
            let b2 = {
                let mut b =
                    BlockBuilder::after(chain.height(), chain.tip_hash()).with_timestamp(20);
                b.push_tx(signed_update_domain(&sk, 1)).unwrap();
                b.push_tx(signed_update_domain(&sk, 2)).unwrap();
                b.build().unwrap()
            };
            chain.push_block(&b2).unwrap();
            chain
        };
        let left = assemble();
        let right = assemble();
        assert_eq!(left.tip_hash(), right.tip_hash());
        assert_eq!(left.state(), right.state());
        assert_eq!(left.height(), 2);
    }

    #[test]
    fn tx_limit_enforced() {
        let mut builder = BlockBuilder::after(0, genesis_hash());
        let sk = SigningKey::from_bytes([1; 32]);
        for i in 0..MAX_TXS_PER_BLOCK {
            builder
                .push_tx(signed_register_domain(&sk, &format!("d{i}.uip")))
                .unwrap();
        }
        assert_eq!(
            builder.push_tx(signed_register_domain(&sk, "overflow.uip")),
            Err(BlockchainError::TooManyTransactions(MAX_TXS_PER_BLOCK + 1))
        );
        assert_eq!(builder.len(), MAX_TXS_PER_BLOCK);
    }

    #[test]
    fn empty_block_builds() {
        let block = BlockBuilder::after(0, genesis_hash()).build().unwrap();
        assert!(block.transactions.is_empty());
        assert_eq!(block.header.height, 1);
    }
}
