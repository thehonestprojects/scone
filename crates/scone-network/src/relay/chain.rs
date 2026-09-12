//! Chain-facing acceptance paths: `accept_block`, `accept_transaction`,
//! the cheap state precheck and the resilient devnet production loop
//! (`produce_if_ready`).
//!
//! Extracted verbatim from `relay.rs` (pass 2 refactor); behavior
//! contracts preserved — see the per-item doc comments (H2 duplicate
//! rules, F1 production resilience). M8b: the precheck mirrors the
//! full state rules, including the network check (`WrongNetwork`) and
//! the PoW/TLD-open preconditions of registrations.

use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use tracing::{debug, info, warn};

use scone_blockchain::{BlockBuilder, TxId};
use scone_core::Transaction;
use scone_protocol::{Block, BlockHash, Message};
use scone_storage::integration as store_integration;

use crate::error::Result;
use crate::mempool::{MAX_PENDING_PER_DOMAIN, domain_key};

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
        // M3 (.bak port): fork-aware attach — a block on a known
        // non-tip parent evaluates a branch switch (tie-break by
        // lowest tip hash) instead of a flat ParentNotTip refusal.
        let applied = self.chain.try_attach(&block)?;
        store_integration::store_block_with_removals(
            &mut self.store,
            &self.chain,
            &block,
            applied.hash,
            &applied.gc_removed_domains,
        )?;
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
        // Anchor loop: propose/sign/aggregate/finalize after every
        // accepted block (no-op for relays without committee state).
        self.anchor_after_block();
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
        // Anti-replay (ported from the .bak): a transaction already
        // included in the chain (within the window) never re-enters
        // a mempool. Typed rejection, logged — a peer relaying stale
        // bytes gets a clean error, never a loop.
        if self.chain.is_tx_included(&id) {
            debug!(
                txid = hex(id.as_bytes()),
                "rejected replayed transaction (already included)"
            );
            return Err(crate::error::NetworkError::Blockchain(
                scone_blockchain::BlockchainError::TxReplay,
            ));
        }
        // Economic anti-spam (ported from the .bak): at most
        // MAX_PENDING_PER_DOMAIN pending transactions per target
        // namespace — an owner cannot fill the mempool for free with
        // UPDATE-type operations on one domain.
        if let Some(key) = domain_key(&tx)
            && self.mempool.count_for_domain(key) >= MAX_PENDING_PER_DOMAIN
        {
            warn!(
                txid = hex(id.as_bytes()),
                cap = MAX_PENDING_PER_DOMAIN,
                "rejected transaction: too many pending for this domain"
            );
            return Err(crate::error::NetworkError::LimitExceeded(
                "mempool per-domain cap",
            ));
        }
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

    /// Cheap state precheck (full rules run again at push time; PoW
    /// verification is skipped here — it is expensive and the block
    /// producer re-runs everything anyway).
    pub(super) fn precheck_state(
        &self,
        tx: &Transaction,
    ) -> std::result::Result<(), scone_blockchain::BlockchainError> {
        use scone_blockchain::BlockchainError;
        // M8b: the network id must match this relay's network — a
        // testnet tx never enters a mainnet mempool (typed
        // `WrongNetwork`, before any other rule).
        if tx.network() != self.chain.network().network_id {
            return Err(BlockchainError::WrongNetwork {
                tx: tx.network(),
                chain: self.chain.network().network_id,
            });
        }
        match tx {
            Transaction::RegisterDomain(r) => {
                // D1 (M7c) + M8b: the TLD of the carried name must be
                // registered AND open for self-registration.
                let tld_id = scone_core::TldId::from_tld(&r.name.tld());
                let Some(tld) = self.chain.state().tld(&tld_id) else {
                    return Err(BlockchainError::UnknownTld);
                };
                if !tld.open {
                    return Err(BlockchainError::TldClosed);
                }
                if self.chain.state().domain(&r.domain_id).is_some() {
                    return Err(BlockchainError::DomainAlreadyRegistered);
                }
                Ok(())
            }
            Transaction::UpdateDomain(u) => {
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
            Transaction::RegisterTld(t) => {
                if self.chain.state().tld(&t.tld_id).is_some() {
                    return Err(BlockchainError::TldAlreadyRegistered);
                }
                Ok(())
            }
            // M8b family: owner-of-record checks against the registry.
            Transaction::TransferTld(t) => {
                let tld = self
                    .chain
                    .state()
                    .tld(&t.tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if tld.owner != t.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                Ok(())
            }
            Transaction::RevokeTld(r) => {
                let tld = self
                    .chain
                    .state()
                    .tld(&r.tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if tld.owner != r.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                Ok(())
            }
            Transaction::SetTldOpen(s) => {
                let tld = self
                    .chain
                    .state()
                    .tld(&s.tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if tld.owner != s.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                Ok(())
            }
            Transaction::AssignDomain(a) => {
                let tld_id = scone_core::TldId::from_tld(&a.name.tld());
                let tld = self
                    .chain
                    .state()
                    .tld(&tld_id)
                    .ok_or(BlockchainError::UnknownTld)?;
                if tld.owner != a.owner {
                    return Err(BlockchainError::NotTldOwner);
                }
                if self.chain.state().domain(&a.domain_id).is_some() {
                    return Err(BlockchainError::DomainAlreadyRegistered);
                }
                Ok(())
            }
            Transaction::RenewDomain(r) => {
                let state = self
                    .chain
                    .state()
                    .domain(&r.domain_id)
                    .ok_or(BlockchainError::UnknownDomain)?;
                if state.owner != r.owner {
                    return Err(BlockchainError::NotOwner);
                }
                Ok(())
            }
            Transaction::TransferDomain(t) => {
                let state = self
                    .chain
                    .state()
                    .domain(&t.domain_id)
                    .ok_or(BlockchainError::UnknownDomain)?;
                if state.owner != t.owner {
                    return Err(BlockchainError::NotOwner);
                }
                Ok(())
            }
            // M9: slash evidence is self-contained — the cryptographic
            // proof was checked by `validate_transaction`; the pool
            // membership rule is enforced at application time.
            Transaction::Slash(_) => Ok(()),
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
    ///    evicted (a stale RegisterDomain/UpdateDomain can never become valid
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
            // 2. Evict stale transactions (state moved since admit)
            //    and replayed ones (a block accepted since admit
            //    already contains this TXID — the push would reject
            //    the whole block with TxReplay).
            let mut candidates: Vec<Transaction> = Vec::with_capacity(drained.len());
            for tx in drained {
                let replayed = scone_blockchain::transaction_id(&tx)
                    .is_ok_and(|id| self.chain.is_tx_included(&id));
                if replayed {
                    warn!("evicted replayed tx from the mempool (already included)");
                    continue;
                }
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
            // end on rejection. Bounded by the candidate count.
            while !candidates.is_empty() {
                // M5: the block must be SIGNED by an allowed producer.
                // The anchor key (a committee member is an allowed
                // producer) when armed, otherwise an ephemeral devnet
                // key — bootstrap production is open (allowed set
                // empty / contains live-domain owners).
                let devnet_key = scone_crypto::SigningKey::from_bytes([
                    0xd0, 0x1d, 0xca, 0x5e, 0xba, 0xdc, 0x0f, 0xfe, 0x7e, 0x11, 0x0b, 0xad, 0x5c,
                    0x0c, 0x0f, 0xfe, 0xe3, 0x0c, 0x0d, 0xe5, 0xca, 0x0f, 0xfe, 0xe0, 0x0b, 0x0a,
                    0xd0, 0xca, 0x5e, 0x0e, 0x0d, 0xe5,
                ]);
                let producer = self.anchor.signing_key().unwrap_or(devnet_key);
                let block = {
                    let mut builder =
                        BlockBuilder::after(self.chain.height(), self.chain.tip_hash())
                            .with_timestamp(unix_now())
                            .with_producer(&producer);
                    for tx in &candidates {
                        builder.push_tx(tx.clone())?;
                    }
                    builder.build()?
                };
                match self.chain.push_block_with_gc(&block) {
                    Ok(applied) => {
                        // Same treatment as accept_block, minus the
                        // now-redundant re-validation: the block was
                        // just pushed; store it (GC removals
                        // included) and relay it.
                        store_integration::store_block_with_removals(
                            &mut self.store,
                            &self.chain,
                            &block,
                            applied.hash,
                            &applied.gc_removed_domains,
                        )?;
                        info!(
                            hash = hex(applied.hash.as_bytes()),
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
                        // Anchor loop: a produced block advances the
                        // chain too — propose/sign/finalize.
                        self.anchor_after_block();
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
