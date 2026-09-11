//! Swarm event handling: identify addresses into Kademlia,
//! request-response messages (the scone-protocol surface), peer
//! connection lifecycle and the bounded sync driver (`GetBlocks`
//! rounds per peer).
//!
//! Extracted verbatim from `relay.rs` (pass 2 refactor); C1
//! hardening unchanged — a single hostile message (bad signature,
//! bad version, invalid block…) must never take the relay down:
//! peer errors are logged and swallowed by the caller, only local
//! fatal failures propagate out of `run`.

use libp2p::PeerId;
use libp2p::identify;
use libp2p::request_response::{Event as ReqResEvent, Message as ReqResMessage};
use libp2p::swarm::SwarmEvent;
use tracing::{debug, info, warn};

use scone_blockchain::block_hash;
use scone_core::SignedDnsRecord;
use scone_protocol::{Message, PROTOCOL_VERSION, decode_complete, encode_to_vec};
use scone_storage::NodeStore;

use crate::behaviour::SconeBehaviourEvent;
use crate::error::{NetworkError, Result};
use crate::sync::serve_blocks;

use super::Relay;
use super::task::SyncState;

/// Maximum sync batches a relay will run against one peer before
/// giving up (bounds the catch-up loop even against a lying peer).
pub const MAX_SYNC_ROUNDS: u32 = 10_000;

impl Relay {
    /// Handles one swarm event.
    pub(super) fn handle_swarm_event(
        &mut self,
        event: SwarmEvent<SconeBehaviourEvent>,
    ) -> Result<()> {
        match event {
            SwarmEvent::Behaviour(SconeBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => {
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                }
            }
            SwarmEvent::Behaviour(SconeBehaviourEvent::Reqres(event)) => {
                self.handle_reqres(event)?;
            }
            SwarmEvent::Behaviour(SconeBehaviourEvent::Kad(event)) => {
                self.handle_kad(event);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if !self.peers.contains(&peer_id) {
                    self.peers.push(peer_id);
                }
                info!(peer = %peer_id, "peer connected");
                // Kick off sync catch-up from our height + 1.
                let from = self.chain.height() + 1;
                self.sync.insert(
                    peer_id,
                    SyncState {
                        next: from,
                        rounds: 0,
                    },
                );
                self.request_sync_batch(peer_id, from);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                debug!(peer = %peer_id, "peer disconnected");
                self.peers.retain(|p| *p != peer_id);
                self.sync.remove(&peer_id);
            }
            _ => {}
        }
        Ok(())
    }

    /// Sends one bounded `GetBlocks` request.
    fn request_sync_batch(&mut self, peer: PeerId, from: u64) {
        let request = Message::GetBlocks {
            start_height: from,
            max_blocks: 1,
        };
        self.swarm
            .behaviour_mut()
            .reqres
            .send_request(&peer, request);
    }

    /// Request-response events (scone-protocol messages).
    fn handle_reqres(&mut self, event: ReqResEvent<Message, Message>) -> Result<()> {
        match event {
            ReqResEvent::Message { message, peer, .. } => match message {
                ReqResMessage::Request {
                    request, channel, ..
                } => {
                    let response = self.handle_peer_message(peer, request)?;
                    self.swarm
                        .behaviour_mut()
                        .reqres
                        .send_response(channel, response)
                        .map_err(|_| NetworkError::Peer("response channel closed".into()))?;
                }
                ReqResMessage::Response { response, .. } => {
                    self.handle_peer_message(peer, response)?;
                }
            },
            ReqResEvent::OutboundFailure { peer, error, .. } => {
                warn!("outbound failure ({peer}): {error}");
                self.sync.remove(&peer);
            }
            ReqResEvent::InboundFailure { error, .. } => {
                warn!("inbound failure: {error}");
            }
            ReqResEvent::ResponseSent { .. } => {}
        }
        Ok(())
    }

    /// Handles one decoded scone-protocol message from `peer`.
    /// Returns the response for requests; one-way messages get a
    /// `Pong` ack.
    fn handle_peer_message(&mut self, peer: PeerId, message: Message) -> Result<Message> {
        match message {
            Message::Hello { version } => {
                if version == 0 || version > PROTOCOL_VERSION {
                    return Err(NetworkError::Peer(format!(
                        "peer {peer} announces version {version}"
                    )));
                }
                Ok(Message::Hello {
                    version: PROTOCOL_VERSION,
                })
            }
            Message::Ping | Message::Pong => Ok(Message::Pong),
            Message::GetBlock { hash } => {
                // Served from the RAM window only (bounded scan);
                // historical-by-hash lookups go through sync by height
                // (documented limitation).
                let found = (1..=self.chain.height())
                    .rev()
                    .filter_map(|h| self.chain.block(h))
                    .find(|b| block_hash(&b.header).map(|bh| bh == hash).unwrap_or(false))
                    .cloned();
                match found {
                    Some(block) => Ok(Message::Block(Box::new(block))),
                    None => Ok(Message::Pong),
                }
            }
            Message::GetBlocks { start_height, .. } => {
                // One block per round trip (bounded); the sync driver
                // iterates.
                let blocks = serve_blocks(&self.chain, &self.store, start_height, 1)?;
                match blocks.into_iter().next() {
                    Some(block) => Ok(Message::Block(Box::new(block))),
                    None => Ok(Message::Pong), // caught up
                }
            }
            Message::Block(block) => {
                let height = block.header.height;
                self.accept_block(*block, Some(peer))?;
                // Continue the batch if this filled our next height.
                if let Some(state) = self.sync.get_mut(&peer)
                    && height == state.next
                {
                    state.next += 1;
                    state.rounds += 1;
                    if state.rounds < MAX_SYNC_ROUNDS {
                        let next = state.next;
                        self.request_sync_batch(peer, next);
                    }
                }
                Ok(Message::Pong)
            }
            Message::Transaction(tx) => {
                self.accept_transaction(tx, Some(peer))?;
                Ok(Message::Pong)
            }
            Message::GetRecord { domain_id } => match self.store.dht_cache(&domain_id)? {
                Some(bytes) => match decode_complete::<SignedDnsRecord>(&bytes) {
                    Ok(record) => Ok(Message::Record(record)),
                    Err(e) => Err(NetworkError::Protocol(e)),
                },
                None => Ok(Message::Pong),
            },
            Message::Record(record) => {
                if self.verify_record_against_chain(&record)? {
                    let encoded = encode_to_vec(&record)?;
                    self.store
                        .put_dht_cache(record.record.domain_id, &encoded)?;
                    Ok(Message::Pong)
                } else {
                    Err(NetworkError::RecordRejected(
                        "record does not match chain state".into(),
                    ))
                }
            }
        }
    }
}
