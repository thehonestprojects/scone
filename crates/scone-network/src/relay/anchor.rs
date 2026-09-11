//! The anchor loop: checkpoint propose / sign / aggregate / gossip /
//! finalize inside the relay.
//!
//! # Model
//!
//! After every accepted or produced block, a relay holding an anchor
//! key (`Config::anchor_key`) that IS in the current committee signs
//! the deterministic checkpoint content (`propose_checkpoint`) via
//! the [`SignerGuard`] (crash-safe, refuses equivocation BEFORE
//! signing) and gossips it. Every relay — anchor or not — accumulates
//! signatures per checkpoint data hash; when the accumulation reaches
//! the committee quorum, the checkpoint is finalized
//! (`accept_checkpoint`) and the complete aggregate is broadcast.
//!
//! # Memory bounds
//!
//! Pending signature sets live in a BTreeMap keyed by data hash,
//! capped at [`MAX_PENDING_CHECKPOINTS`] entries — beyond the cap the
//! smallest key (in practice the stalest epoch) is evicted. Each
//! entry is bounded by the wire limit on signers. Every network-driven
//! failure is logged and swallowed: a hostile `Checkpoint` message
//! must never take the relay down.
//!
//! A relay WITHOUT an anchor key still participates in finality: it
//! accumulates, finalizes and relays checkpoints; it just never signs.

use std::collections::BTreeMap;

use libp2p::PeerId;
use tracing::{debug, info, warn};

use scone_blockchain::SignerGuard;
use scone_core::checkpoint::{Checkpoint, CheckpointData};
use scone_core::{MIN_FINALITY_COMMITTEE_SIZE, quorum_for};
use scone_crypto::{PublicKey, Signature, SigningKey};
use scone_protocol::Message;

use super::Relay;
use super::hex::hex;

/// Maximum simultaneously tracked pending checkpoints (signature
/// accumulation). Above this cap entries are evicted (smallest data
/// hash first): an attacker spamming distinct checkpoint datas cannot
/// grow the relay memory unboundedly.
pub const MAX_PENDING_CHECKPOINTS: usize = 256;

/// The anchor state of a relay: signing material (when configured)
/// and the pending signature aggregates (always present — finality is
/// observed by every node).
pub(super) struct AnchorLoop {
    /// Anchor signing key (None = this relay never signs).
    anchor: Option<AnchorKey>,
    /// Crash-safe signing guard (refuses double-signing across
    /// restarts). Present only with `anchor`.
    guard: Option<SignerGuard>,
    /// Signatures accumulated per checkpoint data signing hash.
    pending: BTreeMap<[u8; 32], PendingCheckpoint>,
}

/// Opened anchor keyfile material.
struct AnchorKey {
    sk: scone_crypto::SigningKey,
    pk: PublicKey,
}

/// One pending (not yet finalized) checkpoint aggregate.
struct PendingCheckpoint {
    data: CheckpointData,
    /// pk -> signature (BTreeMap: dedup by signer, canonical order).
    signatures: BTreeMap<PublicKey, Signature>,
}

impl AnchorLoop {
    /// Loads the anchor key (if configured) and the signer guard from
    /// the data dir (`signer-state.dat`). A keyfile that cannot be
    /// opened (missing passphrase env, wrong passphrase, bad file) is
    /// a LOCAL configuration issue: the caller gets the error so the
    /// operator notices at startup, instead of a silently unarmed
    /// anchor.
    pub(super) fn load(config: &crate::config::Config) -> crate::error::Result<Self> {
        let Some(path) = &config.anchor_key else {
            return Ok(Self::passive());
        };
        let passphrase = std::env::var(&config.anchor_passphrase_env).map_err(|_| {
            crate::error::NetworkError::Peer(format!(
                "anchor keyfile {} configured but passphrase env '{}' is unset",
                path.display(),
                config.anchor_passphrase_env
            ))
        })?;
        let sk = scone_keystore::open(path, &passphrase).map_err(|e| {
            warn!("anchor keyfile could not be opened: {e}");
            e
        })?;
        let pk = sk.public_key();
        info!(anchor = %pk, "anchor loop armed");
        Ok(Self {
            anchor: Some(AnchorKey { sk, pk }),
            guard: Some(SignerGuard::load(&config.data_dir)),
            pending: BTreeMap::new(),
        })
    }

    /// Passive loop: accumulates and finalizes, never signs.
    fn passive() -> Self {
        Self {
            anchor: None,
            guard: None,
            pending: BTreeMap::new(),
        }
    }

    /// The signing key block production should sign with: the anchor
    /// key when armed (a committee member is an allowed producer),
    /// None for a passive relay (the caller falls back to an
    /// ephemeral devnet key).
    pub(super) fn signing_key(&self) -> Option<SigningKey> {
        self.anchor.as_ref().map(|a| a.sk.clone())
    }

    /// Merges `signatures` into the pending set of `data`. Returns
    /// true if at least one signature was new (callers relay the
    /// message only then, cutting gossip loops).
    fn merge(&mut self, data: CheckpointData, signatures: Vec<(PublicKey, Signature)>) -> bool {
        let hash = data.signing_hash();
        let entry = self
            .pending
            .entry(hash)
            .or_insert_with(|| PendingCheckpoint {
                data,
                signatures: BTreeMap::new(),
            });
        let before = entry.signatures.len();
        entry.signatures.extend(signatures);
        entry.signatures.len() != before
    }

    /// Drops the pending entry for `hash` (after finalization or
    /// invalidation).
    fn drop_pending(&mut self, hash: &[u8; 32]) {
        self.pending.remove(hash);
    }

    /// Evicts entries above the cap (smallest data hash first).
    fn enforce_cap(&mut self) {
        while self.pending.len() > MAX_PENDING_CHECKPOINTS {
            let oldest = *self.pending.keys().next().expect("len > cap checked");
            self.pending.remove(&oldest);
        }
    }

    /// Builds the aggregate checkpoint for `hash` if enough committee
    /// signatures were accumulated. Non-committee signatures cannot
    /// help reach the quorum and are left out of the broadcast.
    fn aggregate_if_quorum(
        &self,
        hash: &[u8; 32],
        committee: &[PublicKey],
        quorum: usize,
    ) -> Option<Checkpoint> {
        let pending = self.pending.get(hash)?;
        let mut signatures: Vec<(PublicKey, Signature)> = pending
            .signatures
            .iter()
            .filter(|(pk, _)| committee.contains(pk))
            .map(|(pk, sig)| (*pk, *sig))
            .collect();
        if signatures.len() < quorum {
            return None;
        }
        signatures.sort_by_key(|(pk, _)| *pk);
        Some(Checkpoint {
            data: pending.data.clone(),
            signatures,
        })
    }
}

impl Relay {
    /// Anchor step after every accepted/produced block: if this node
    /// is in the current committee and the chain is ready, sign the
    /// deterministic content and gossip it; then (also for passive
    /// relays) try to finalize from the accumulated signatures.
    /// Nothing here is fatal: the anchor loop must not take the relay
    /// down (worst case finality is deferred).
    pub(super) fn anchor_after_block(&mut self) {
        self.try_propose_checkpoint();
        self.try_finalize_all();
        self.anchor.enforce_cap();
    }

    /// Proposes + signs + gossips when this relay is an armed anchor
    /// of the current committee. The committee must also be large
    /// enough to ever claim finality (≥ MIN_FINALITY_COMMITTEE_SIZE):
    /// a smaller one would have `accept_checkpoint` refuse the
    /// checkpoint forever, while the signer guard would have burned
    /// this epoch's signature — a deadlock. Signing goes through the
    /// guard: a refusal (equivocation guard) is logged and the relay
    /// stays silent for the epoch — never double-sign.
    fn try_propose_checkpoint(&mut self) {
        let Some(key) = self.anchor.anchor.as_ref() else {
            return;
        };
        let pk = key.pk;
        let committee = self.chain.committee(0);
        if committee.len() < MIN_FINALITY_COMMITTEE_SIZE {
            return; // finality deferred by design: do not burn the epoch
        }
        if !committee.contains(&pk) {
            return; // not in the current committee: nothing to sign
        }
        let Some(data) = self.chain.propose_checkpoint() else {
            return; // epoch_min_blocks not reached
        };
        let hash = data.signing_hash();
        // Disjoint field borrows: the chain is read, the guard mutated.
        let Some(guard) = self.anchor.guard.as_mut() else {
            return;
        };
        let sk = key.sk.clone();
        match self.chain.sign_checkpoint(guard, &sk, &data) {
            Ok(sig) => {
                debug!(
                    hash = hex(&hash),
                    epoch = data.epoch,
                    "signed checkpoint proposal"
                );
                let cp = Checkpoint {
                    data: data.clone(),
                    signatures: vec![(pk, sig)],
                };
                // Gossip only on the FIRST signature of this content
                // (re-signing after a restart is idempotent and must
                // not re-flood the network).
                let first = self.anchor.merge(data, vec![(pk, sig)]);
                if first {
                    self.broadcast_checkpoint(&cp, None);
                }
            }
            Err(e) => warn!("checkpoint signing refused: {e}"),
        }
    }

    /// Attempts finalization of every pending aggregate whose data
    /// still passes the chain rules.
    fn try_finalize_all(&mut self) {
        let hashes: Vec<[u8; 32]> = self.anchor.pending.keys().copied().collect();
        for hash in hashes {
            let Some(pending) = self.anchor.pending.get(&hash) else {
                continue;
            };
            let recovery = pending.data.recovery;
            if self.chain.check_checkpoint_data(&pending.data).is_err() {
                // Stale or invalid for our chain: drop, wait for the
                // next round.
                self.anchor.drop_pending(&hash);
                continue;
            }
            let committee = self.chain.committee(recovery);
            let quorum = quorum_for(committee.len());
            let Some(cp) = self.anchor.aggregate_if_quorum(&hash, &committee, quorum) else {
                continue;
            };
            match self.chain.accept_checkpoint(cp.clone()) {
                Ok(true) => {
                    info!(
                        hash = hex(&hash),
                        epoch = cp.data.epoch,
                        height = cp.data.height,
                        signers = cp.signatures.len(),
                        "checkpoint FINALIZED"
                    );
                    self.anchor.drop_pending(&hash);
                    self.broadcast_checkpoint(&cp, None);
                }
                Ok(false) => {
                    // Exact duplicate of our last finalized: done.
                    self.anchor.drop_pending(&hash);
                }
                Err(e) => {
                    // Content rules re-checked and failed (committee
                    // below the BFT floor, state moved…): drop and
                    // wait; finality is deferred, never forced.
                    debug!("checkpoint not accepted: {e}");
                    self.anchor.drop_pending(&hash);
                }
            }
        }
    }

    /// Broadcasts one checkpoint (partial aggregate or finalized) to
    /// every connected peer except `skip`.
    fn broadcast_checkpoint(&mut self, cp: &Checkpoint, skip: Option<PeerId>) {
        let message = Message::Checkpoint(Box::new(cp.clone()));
        for peer in self.peers.iter().filter(|p| Some(**p) != skip) {
            self.swarm
                .behaviour_mut()
                .reqres
                .send_request(peer, message.clone());
        }
    }

    /// Acceptance path of a gossiped checkpoint: verify the data
    /// against our chain, merge the signatures, finalize on quorum,
    /// relay while new signatures are learned. All failures are typed
    /// errors (logged and swallowed by the swarm layer) — a hostile
    /// message must never take the relay down.
    pub(super) fn accept_checkpoint_message(
        &mut self,
        cp: Checkpoint,
        from: Option<PeerId>,
    ) -> crate::error::Result<()> {
        // Already finalized here: exact duplicate of our window —
        // silently absorbed (no re-broadcast: gossip loop cut).
        if self
            .chain
            .checkpoint_window()
            .iter()
            .any(|c| c.data == cp.data)
        {
            return Ok(());
        }
        // Data rules first (height in our chain, chaining, recovery
        // bounds): junk data never touches the accumulator.
        self.chain
            .check_checkpoint_data(&cp.data)
            .map_err(crate::error::NetworkError::Blockchain)?;
        let hash = cp.data.signing_hash();
        let data = cp.data.clone();
        let signatures = cp.signatures.clone();
        let new = self.anchor.merge(data, signatures);
        self.anchor.enforce_cap();
        if new {
            debug!(
                hash = hex(&hash),
                from = from.as_ref().map(ToString::to_string),
                "checkpoint signatures merged"
            );
        }
        self.try_finalize_all();
        // Relay only while new signatures are learned (loop cut), and
        // never if it got finalized (the finalized broadcast of this
        // node already covers the peers).
        if new
            && self
                .chain
                .checkpoint_window()
                .iter()
                .all(|c| c.hash() != hash)
        {
            self.broadcast_checkpoint(&cp, from);
        }
        Ok(())
    }

    /// `GetCheckpoints` handler: serves the finalized window, oldest
    /// first — every checkpoint but the last is pushed as its own
    /// request to the asking peer, the last one is the response (the
    /// request-response protocol carries exactly one reply).
    pub(super) fn handle_get_checkpoints(&mut self, peer: PeerId) -> crate::error::Result<Message> {
        let window: Vec<Checkpoint> = self.chain.checkpoint_window().to_vec();
        let mut iter = window.into_iter().peekable();
        let mut last = Message::Pong; // empty window: caught up
        while let Some(cp) = iter.next() {
            let message = Message::Checkpoint(Box::new(cp));
            if iter.peek().is_some() {
                self.swarm
                    .behaviour_mut()
                    .reqres
                    .send_request(&peer, message);
            } else {
                last = message;
            }
        }
        Ok(last)
    }
}
