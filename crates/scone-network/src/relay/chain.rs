//! Chain-facing acceptance paths: `accept_block`, `accept_transaction`,
//! the cheap state precheck and the resilient devnet production loop
//! (`produce_if_ready`).
//!
//! Extracted verbatim from `relay.rs` (pass 2 refactor); behavior
//! contracts preserved — see the per-item doc comments (H2 duplicate
//! rules, F1 production resilience).

use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use tracing::{debug, info, warn};

use scone_blockchain::{BlockBuilder, TxId};
use scone_core::Transaction;
use scone_protocol::{Block, BlockHash, Message};
use scone_storage::integration as store_integration;

use crate::error::Result;

use super::Relay;
use super::hex::hex;

impl Relay {
    /// Full acceptance path of a block (P2P or self-produced):
    /// validate → store → broadcast → reconcile mempool.
    ///
    /// H2 (explicit): a duplicate of an already-canonical block is
    /// detected **before** `push_block` (which would incidentally
    /// reject it via `ParentNotTip`) and answered as a no-op — the
    /// block is NOT re-broadcast, mirroring the transaction rule.
    /// Hashes are recomputed, never taken from the wire.
    pub(super) fn accept_block(&mut self, block: Block, from: Option<PeerId>) -> Result<BlockHash> {
        let hash = scone_blockchain::block_hash(&block.header)?;
        if block.header.height <= self.chain.height()
            && self
                .chain
                .block(block.header.height)
                .is_some_and(|canonical| {
                    scone_blockchain::block_hash(&canonical.header) == Ok(hash)
                })
        {
            return Ok(hash); // already canonical: no store, no relay
        }
        let hash = self.chain.push_block(&block)?;
        store_integration::store_block(&mut self.store, &self.chain, &block, hash)?;
        info!(
            hash = hex(hash.as_bytes()),
            height = block.header.height,
            txs = block.transactions.len(),
            from = from.map(|p| p.to_string()).unwrap_or_else(|| "self".into()),
            "accepted block"
        );
        for tx in &block.transactions {
            if let Ok(id) = scone_blockchain::transaction_id(tx) {
                self.mempool.remove(&id);
            }
        }
        let message = Message::Block(Box::new(block));
        for peer in self.peers.iter().filter(|p| Some(**p) != from) {
            self.swarm
                .behaviour_mut()
                .reqres
                .send_request(peer, message.clone());
        }
        Ok(hash)
    }

    /// Full acceptance path of a transaction: validate → precheck →
    /// mempool → broadcast.
    ///
    /// H2: the broadcast happens **only if the mempool actually
    /// inserted the transaction** (first sighting). Relaying a
    /// duplicate would loop forever on a cycle of 3+ peers
    /// (A→B→C→A→B→…), each hop being a fresh request-response with a
    /// full Ed25519 revalidation.
    pub(super) fn accept_transaction(
        &mut self,
        tx: Transaction,
        from: Option<PeerId>,
    ) -> Result<TxId> {
        scone_blockchain::validate_transaction(&tx)?;
        self.precheck_state(&tx)
            .map_err(crate::error::NetworkError::Blockchain)?;
        let id = scone_blockchain::transaction_id(&tx)?;
        if !self.mempool.insert(id, tx.clone())? {
            // Duplicate: already pooled (and already broadcast when
            // first seen). Do NOT relay again.
            return Ok(id);
        }
        debug!(txid = hex(id.as_bytes()), "accepted transaction");
        let message = Message::Transaction(tx);
        for peer in self.peers.iter().filter(|p| Some(**p) != from) {
            self.swarm
                .behaviour_mut()
                .reqres
                .send_request(peer, message.clone());
        }
        Ok(id)
    }

    /// Cheap state precheck (full rules run again at push time).
    pub(super) fn precheck_state(
        &self,
        tx: &Transaction,
    ) -> std::result::Result<(), scone_blockchain::BlockchainError> {
        use scone_blockchain::BlockchainError;
        match tx {
            Transaction::Register(r) => {
                if self.chain.state().domain(&r.domain_id).is_some() {
                    return Err(BlockchainError::DomainAlreadyRegistered);
                }
                Ok(())
            }
            Transaction::Update(u) => {
                let state = self
                    .chain
                    .state()
                    .domain(&u.domain_id)
                    .ok_or(BlockchainError::UnknownDomain)?;
                if state.sequence + 1 != u.sequence {
                    return Err(BlockchainError::InvalidSequence {
                        expected: state.sequence + 1,
                        got: u.sequence,
                    });
                }
                if state.owner != u.owner {
                    return Err(BlockchainError::NotOwner);
                }
                Ok(())
            }
        }
    }

    /// Devnet production: mempool non-empty → assemble a block the
    /// canonical chain ACCEPTS, then treat it exactly like a received
    /// block (store + broadcast).
    ///
    /// M5 fix-up (F1, crash prouvé par
    /// `concurrent_registers_never_kill_the_producer`): production is
    /// resilient. Two racers for one name both pass the admit-time
    /// precheck and sit in the mempool; a block containing both is
    /// rejected WHOLE by `push_block` (`DomainAlreadyRegistered`) —
    /// propagating that error killed the relay. Instead:
    ///
    /// 1. transactions gone stale w.r.t. the CURRENT state are
    ///    evicted (a stale Register/Update can never become valid
    ///    again — the state only moves forward);
    /// 2. the candidate list shrinks from the end while the chain
    ///    rejects the block (intra-block conflict), the conflicting
    ///    transaction is dropped with a log — never fatal.
    ///
    /// Every candidate passes the precheck alone, so a one-transaction
    /// block always applies and both loops terminate. Only genuinely
    /// local failures (builder, store) still propagate out of `run`.
    pub(super) fn produce_if_ready(&mut self) -> Result<()> {
        while !self.mempool.is_empty() {
            // 1. Drain one block's worth (bounded).
            let drained = self
                .mempool
                .drain_up_to(scone_protocol::limits::MAX_TXS_PER_BLOCK);
            // 2. Evict stale transactions (state moved since admit).
            let mut candidates: Vec<Transaction> = Vec::with_capacity(drained.len());
            for tx in drained {
                match self.precheck_state(&tx) {
                    Ok(()) => candidates.push(tx),
                    Err(e) => {
                        warn!("evicted stale tx from the mempool: {e}");
                    }
                }
            }
            if candidates.is_empty() {
                // Nothing buildable in this batch; the mempool may
                // still hold more (it shrank: the stale ones are gone).
                continue;
            }
            // 3. Greedy assembly: full list first, shrink from the
            //    end on rejection. Bounded by the candidate count.
            while !candidates.is_empty() {
                let block = {
                    let mut builder =
                        BlockBuilder::after(self.chain.height(), self.chain.tip_hash())
                            .with_timestamp(unix_now());
                    for tx in &candidates {
                        builder.push_tx(tx.clone())?;
                    }
                    builder.build()?
                };
                match self.chain.push_block(&block) {
                    Ok(hash) => {
                        // Same treatment as accept_block, minus the
                        // now-redundant re-validation: the block was
                        // just pushed; store it and relay it.
                        store_integration::store_block(&mut self.store, &self.chain, &block, hash)?;
                        info!(
                            hash = hex(hash.as_bytes()),
                            height = block.header.height,
                            txs = block.transactions.len(),
                            "produced block"
                        );
                        let message = Message::Block(Box::new(block));
                        for peer in &self.peers {
                            self.swarm
                                .behaviour_mut()
                                .reqres
                                .send_request(peer, message.clone());
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        candidates.pop();
                        warn!("dropped conflicting tx from block production: {e}");
                    }
                }
            }
        }
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
