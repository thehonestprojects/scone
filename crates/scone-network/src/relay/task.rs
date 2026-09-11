//! Shared plumbing of the relay task: [`RelayCommand`], the
//! [`Dispatched`] outcome, the [`DhtWaiter`] parked-lookup state and
//! the [`SyncState`] per-peer sync driver.
//!
//! These types were extracted verbatim from `relay.rs` (pass 2
//! refactor); the ownership model is unchanged — the relay task owns
//! everything and the RPC server forwards requests over an mpsc
//! channel.

use std::time::Duration;

use libp2p::kad;
use tokio::sync::oneshot;

use crate::rpc::{RpcRequest, RpcResponse};

/// Hard cap on a DHT lookup before the waiter is failed.
pub(super) const DHT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A parked RPC `get_record` query: the reply channel of the RPC
/// connection, the Kademlia query it waits on (H1: answers are bound
/// to their query — no cross-talk between concurrent lookups), the
/// domain actually requested (H1: the record key is checked against
/// it before any on-chain verification) and its expiry deadline.
pub(super) struct DhtWaiter {
    pub(super) id: kad::QueryId,
    pub(super) domain_id: scone_core::DomainId,
    pub(super) reply: Option<oneshot::Sender<RpcResponse>>,
    deadline: tokio::time::Instant,
}

impl DhtWaiter {
    pub(super) fn fresh(id: kad::QueryId, domain_id: scone_core::DomainId) -> Self {
        Self {
            id,
            domain_id,
            reply: None,
            deadline: tokio::time::Instant::now() + DHT_LOOKUP_TIMEOUT,
        }
    }

    pub(super) fn with_reply(mut self, reply: oneshot::Sender<RpcResponse>) -> Self {
        self.reply = Some(reply);
        self
    }

    pub(super) fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub(super) fn send(mut self, response: RpcResponse) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(response);
        }
    }
}

/// Outcome of dispatching one control request.
pub(super) enum Dispatched {
    /// Answer ready now.
    Now(RpcResponse),
    /// A DHT lookup was started; reply when it resolves.
    Dht(DhtWaiter),
}

/// Command sent by the RPC server task to the relay task.
pub(super) struct RelayCommand {
    pub(super) request: RpcRequest,
    pub(super) reply: oneshot::Sender<RpcResponse>,
}

/// Sync driver state of one peer.
#[derive(Debug, Clone, Copy)]
pub(super) struct SyncState {
    /// Next height to request from this peer.
    pub(super) next: u64,
    /// Batches served by this peer so far (DoS guard).
    pub(super) rounds: u32,
}
