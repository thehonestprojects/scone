//! The relay: a libp2p node that keeps the canonical chain (RAM +
//! [`NodeStore`](scone_storage::NodeStore)), relays transactions and
//! blocks, produces devnet blocks, serves bounded sync,
//! publishes/resolves records in the DHT and answers the local
//! control RPC.
//!
//! ## Event flow
//!
//! - **inbound tx** (RPC `submit_tx` or P2P `Transaction`) → local
//!   validation (`validate_transaction` + state precheck) → mempool
//!   (bounded, dedup by [`TxId`](scone_blockchain::TxId)) → broadcast
//!   to peers;
//! - **inbound block** (P2P `Block` or sync) → `push_block` (full
//!   existing validation) → on accept: `store_block` (atomic delta) +
//!   broadcast + mempool reconciliation;
//! - **production** (devnet, every `produce_interval`): if the
//!   mempool is non-empty, assemble a block with `BlockBuilder`
//!   (timestamp = now; the `PermissiveConsensus` rules apply at
//!   push) and treat it exactly like a received block;
//! - **sync**: when a peer connects, ask `GetBlocks(from = height +
//!   1)`; each response carries one block; repeat until the peer has
//!   nothing more (bounded by [`MAX_SYNC_ROUNDS`]).
//!
//! Every network input is bounded and strictly decoded; nothing
//! panics on remote data.
//!
//! ## Ownership model
//!
//! The relay owns the chain, store, mempool and swarm in ONE task
//! (`Relay::run`). The RPC server forwards requests to that task over
//! an mpsc channel; answers come back over a oneshot per request. No
//! shared mutable state, no lock across swarm polling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::kad;
use libp2p::request_response::{Event as ReqResEvent, Message as ReqResMessage};
use libp2p::swarm::SwarmEvent;
use libp2p::{PeerId, Swarm, identify};
use scone_blockchain::{BlockBuilder, Blockchain, TxId, block_hash, transaction_id};
use scone_core::{DomainId, DomainName, SignedDnsRecord, Transaction};
use scone_protocol::{Block, BlockHash, Message, PROTOCOL_VERSION, decode_complete, encode_to_vec};
use scone_storage::{NodeStore, RedbStore, integration as store_integration};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::behaviour::{
    SconeBehaviour, SconeBehaviourEvent, build_behaviour, parse_bootstrap_addr,
};
use crate::config::{Config, MAX_DHT_WAITERS, MAX_RPC_CONNECTIONS};
use crate::error::{NetworkError, Result};
use crate::mempool::Mempool;
use crate::rpc::{self, RpcRequest, RpcResponse};
use crate::sync::serve_blocks;

/// Maximum sync batches a relay will run against one peer before
/// giving up (bounds the catch-up loop even against a lying peer).
pub const MAX_SYNC_ROUNDS: u32 = 10_000;

/// Hard cap on a DHT lookup before the waiter is failed.
const DHT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

/// A parked RPC `get_record` query: the reply channel of the RPC
/// connection, the Kademlia query it waits on (H1: answers are bound
/// to their query — no cross-talk between concurrent lookups), the
/// domain actually requested (H1: the record key is checked against
/// it before any on-chain verification) and its expiry deadline.
struct DhtWaiter {
    id: kad::QueryId,
    domain_id: DomainId,
    reply: Option<oneshot::Sender<RpcResponse>>,
    deadline: tokio::time::Instant,
}

impl DhtWaiter {
    fn fresh(id: kad::QueryId, domain_id: DomainId) -> Self {
        Self {
            id,
            domain_id,
            reply: None,
            deadline: tokio::time::Instant::now() + DHT_LOOKUP_TIMEOUT,
        }
    }

    fn with_reply(mut self, reply: oneshot::Sender<RpcResponse>) -> Self {
        self.reply = Some(reply);
        self
    }

    fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    fn send(mut self, response: RpcResponse) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(response);
        }
    }
}

/// Outcome of dispatching one control request.
enum Dispatched {
    /// Answer ready now.
    Now(RpcResponse),
    /// A DHT lookup was started; reply when it resolves.
    Dht(DhtWaiter),
}

/// Command sent by the RPC server task to the relay task.
struct RelayCommand {
    request: RpcRequest,
    reply: oneshot::Sender<RpcResponse>,
}

/// Sync driver state of one peer.
#[derive(Debug, Clone, Copy)]
struct SyncState {
    /// Next height to request from this peer.
    next: u64,
    /// Batches served by this peer so far (DoS guard).
    rounds: u32,
}

/// A relay under construction or between polls.
pub struct Relay {
    config: Config,
    store: RedbStore,
    chain: Blockchain,
    mempool: Mempool,
    swarm: Swarm<SconeBehaviour>,
    peers: Vec<PeerId>,
    rpc_addr: std::net::SocketAddr,
    /// Sync driver state per peer.
    sync: HashMap<PeerId, SyncState>,
    /// Pending DHT `get_record` waiters (one per RPC query), with
    /// their expiry deadline.
    dht_waiters: Vec<DhtWaiter>,
}

impl Relay {
    /// Creates the relay: opens/creates the store, loads the chain
    /// (`load_chain`: O(1) tip read + paged state), builds the libp2p
    /// swarm, registers bootstrap addresses in Kademlia.
    ///
    /// # Errors
    ///
    /// [`NetworkError`] on storage, transport or address failures.
    pub fn new(config: Config) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let store = RedbStore::open(config.data_dir.join("chain.redb"))?;
        let chain = store_integration::load_chain(&store)?;
        let mempool = Mempool::new(config.mempool_capacity);
        let rpc_addr = config.rpc_addr;

        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_quic()
            .with_behaviour(build_behaviour)
            .map_err(|e| NetworkError::Peer(format!("swarm init: {e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();

        let listen = config
            .listen
            .clone()
            .unwrap_or_else(|| "/ip4/0.0.0.0/udp/0/quic-v1".to_string());
        swarm
            .listen_on(
                listen
                    .parse()
                    .map_err(|e| NetworkError::Peer(format!("listen '{listen}': {e}")))?,
            )
            .map_err(|e| NetworkError::Peer(format!("listen '{listen}': {e}")))?;

        let mut relay = Self {
            config,
            store,
            chain,
            mempool,
            swarm,
            peers: Vec::new(),
            rpc_addr,
            sync: HashMap::new(),
            dht_waiters: Vec::new(),
        };

        for addr in &relay.config.bootstrap.clone() {
            let (peer, address) = parse_bootstrap_addr(addr)?;
            relay.swarm.add_peer_address(peer, address.clone());
            relay.swarm.behaviour_mut().kad.add_address(&peer, address);
        }
        Ok(relay)
    }

    /// Local peer id.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// P2P listen multiaddr of this relay, once bound (M5: lets the
    /// CLI print a ready-to-use `--bootstrap` value for other nodes).
    ///
    /// # Errors
    ///
    /// [`NetworkError::Peer`] when no address is (yet) bound.
    pub fn listen_addr(&self) -> Result<libp2p::Multiaddr> {
        self.swarm
            .listeners()
            .next()
            .cloned()
            .ok_or_else(|| NetworkError::Peer("no listen address".into()))
    }

    /// Waits until the QUIC listener is bound; returns the multiaddr
    /// (tests use it to bootstrap node B onto node A).
    ///
    /// # Errors
    ///
    /// [`NetworkError::timeout`] if no address appears in time.
    pub async fn wait_listen_addr(&mut self) -> Result<libp2p::Multiaddr> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if let std::task::Poll::Ready(SwarmEvent::NewListenAddr { address, .. }) =
                futures::poll!(self.swarm.select_next_some())
            {
                return Ok(address);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(NetworkError::timeout("listen address"))
    }

    /// Runs the relay until the process is stopped: swarm events,
    /// devnet production tick, RPC server.
    ///
    /// # Errors
    ///
    /// [`NetworkError`] on fatal swarm/store failures.
    pub async fn run(mut self) -> Result<()> {
        // Ensure the P2P listener is bound before announcing anything
        // (libp2p only reports the address once the swarm is polled;
        // the events consumed here are pre-connection and carry no
        // application traffic).
        let p2p_addr = self.wait_listen_addr().await.ok();
        let listener = rpc::bind(self.config.rpc_addr).await?;
        self.rpc_addr = listener.local_addr()?;
        info!(
            peer = %self.peer_id(),
            rpc_addr = %self.rpc_addr,
            "rpc listening"
        );
        // Best-effort echo of the P2P address for `--bootstrap`.
        if let Some(addr) = p2p_addr {
            info!(
                peer = %self.peer_id(),
                p2p_addr = format!("{addr}/p2p/{}", self.peer_id()),
                "p2p listening"
            );
            // Machine-readable contract (stdout = command data, not a
            // log): one `p2p: <multiaddr>` line as soon as the
            // listener is bound, for scripts and the e2e tests. Rust's
            // stdout is line-buffered, so the line is flushed at once.
            println!("p2p: {addr}/p2p/{}", self.peer_id());
        }

        // RPC → relay command channel.
        let (command_tx, mut command_rx) = mpsc::channel::<RelayCommand>(64);

        // ---- UDP DNS surface (M6), optional -------------------------
        // The DNS server talks to the relay core through the same
        // local RPC as the CLI (`ResolveLocal`: one round trip,
        // verified, no parked DHT waiter) — the verified path stays
        // single and identical for every consumer.
        let dns_task: Option<tokio::task::JoinHandle<()>> = match self.config.dns_addr {
            Some(dns_addr) => {
                let upstreams = crate::dns::parse_upstreams(&self.config.dns_upstreams)?;
                let socket = Arc::new(UdpSocket::bind(dns_addr).await?);
                let dns_listen = socket.local_addr()?;
                info!(
                    peer = %self.peer_id(),
                    dns_addr = %dns_listen,
                    upstreams = upstreams.len(),
                    "dns listening (udp)"
                );
                // Machine-readable contract, mirroring `p2p:`.
                println!("dns: {dns_listen}");
                let rpc_client = crate::rpc::RpcClient::new(self.rpc_addr);
                let resolver: crate::dns::Resolver = Arc::new(move |name| {
                    let client = rpc_client.clone();
                    Box::pin(async move {
                        match client
                            .request(crate::rpc::RpcRequest::ResolveLocal { name })
                            .await
                        {
                            Ok(crate::rpc::RpcResponse::Ok { data }) => {
                                let registered = data["registered"].as_bool().unwrap_or(false);
                                let mut rdata = Vec::new();
                                for entry in data["dns"].as_array().unwrap_or(&Vec::new()) {
                                    if let (Some(tc), Some(hex)) =
                                        (entry["type"].as_u64(), entry["rdata"].as_str())
                                        && let Ok(bytes) = decode_hex_static(hex)
                                        && let Ok(tc) = u16::try_from(tc)
                                    {
                                        rdata.push((tc, bytes));
                                    }
                                }
                                if registered {
                                    Ok(Some(crate::dns::Resolved {
                                        rdata,
                                        registered: true,
                                    }))
                                } else {
                                    Ok(None)
                                }
                            }
                            Ok(crate::rpc::RpcResponse::Error { message }) => {
                                Err(format!("relay rpc: {message}"))
                            }
                            Err(e) => Err(format!("relay rpc unreachable: {e}")),
                        }
                    })
                });
                let cache = Arc::new(tokio::sync::Mutex::new(crate::dns::Cache::new()));
                Some(tokio::spawn(async move {
                    if let Err(e) = crate::dns::run_udp(socket, resolver, upstreams, cache).await {
                        warn!("dns server ended: {e}");
                    }
                }))
            }
            None => None,
        };

        // RPC accept loop (one task per connection, M2: at most
        // MAX_RPC_CONNECTIONS concurrent — extra connections wait for
        // a slot instead of exhausting fds/memory).
        let conn_slots = Arc::new(tokio::sync::Semaphore::new(MAX_RPC_CONNECTIONS));
        let rpc_task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let Ok(slot) = conn_slots.clone().try_acquire_owned() else {
                    // At capacity: shed politely. The client sees a
                    // closed connection and its 60 s timeout drives
                    // the retry, no task is spawned.
                    continue;
                };
                let mut tx = command_tx.clone();
                tokio::spawn(async move {
                    let _ = rpc::serve_connection(&mut stream, |req| async move {
                        let (reply_tx, reply_rx) = oneshot::channel();
                        if futures::SinkExt::send(
                            &mut tx,
                            RelayCommand {
                                request: req,
                                reply: reply_tx,
                            },
                        )
                        .await
                        .is_err()
                        {
                            return RpcResponse::error("relay core unavailable");
                        }
                        match reply_rx.await {
                            Ok(response) => response,
                            Err(_) => RpcResponse::error("relay core dropped the request"),
                        }
                    })
                    .await;
                    drop(slot); // free the connection slot
                });
            }
        });
        // The accept loop runs for the life of the process; hold the
        // join handle so the task is not detached silently.
        tokio::pin!(rpc_task);
        let _dns_task = dns_task; // held for the life of the relay

        let mut produce_ticker = tokio::time::interval(self.config.produce_interval);
        produce_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; skip it so a freshly started
        // relay does not produce an empty block before any tx.
        produce_ticker.reset_after(self.config.produce_interval);

        // What woke us up.
        enum Wake {
            Command(RelayCommand),
            Swarm(Box<SwarmEvent<SconeBehaviourEvent>>),
            Produce,
            DhtExpire,
        }

        loop {
            let wake = {
                let dht_deadline = self.next_dht_deadline();
                tokio::select! {
                    command = command_rx.select_next_some() => Wake::Command(command),
                    event = self.swarm.select_next_some() => Wake::Swarm(Box::new(event)),
                    _ = produce_ticker.tick() => Wake::Produce,
                    _ = async {
                        match dht_deadline {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending().await,
                        }
                    } => Wake::DhtExpire,
                }
            };
            // All select! borrows are over: mutate self freely.
            match wake {
                Wake::Command(command) => {
                    let RelayCommand { request, reply } = command;
                    // Dispatch is fully synchronous: DHT queries park
                    // their waiters and resolve through kad events
                    // (a deadline timer fires timeout replies), so
                    // the swarm keeps being polled during lookups.
                    match self.dispatch(request) {
                        Dispatched::Now(response) => {
                            let _ = reply.send(response);
                        }
                        Dispatched::Dht(waiter) => {
                            self.dht_waiters.push(waiter.with_reply(reply));
                        }
                    }
                }
                Wake::Swarm(event) => {
                    // C1: a single hostile message (bad signature, bad
                    // version, invalid block…) must never take the
                    // relay down. Swarm/peer errors are logged and
                    // swallowed; only local fatal failures (store,
                    // production) still propagate out of run().
                    if let Err(e) = self.handle_swarm_event(*event) {
                        warn!("dropped misbehaving network input: {e}");
                    }
                }
                Wake::Produce => {
                    self.produce_if_ready()?;
                }
                Wake::DhtExpire => {
                    self.expire_stale_dht_waiters();
                }
            }
        }
    }

    /// Earliest deadline of the parked DHT waiters, if any.
    fn next_dht_deadline(&self) -> Option<tokio::time::Instant> {
        self.dht_waiters.iter().map(DhtWaiter::deadline).min()
    }

    /// Fails every waiter whose deadline has passed.
    fn expire_stale_dht_waiters(&mut self) {
        let now = tokio::time::Instant::now();
        let mut i = 0;
        while i < self.dht_waiters.len() {
            if self.dht_waiters[i].deadline() <= now {
                let waiter = self.dht_waiters.swap_remove(i);
                waiter.send(RpcResponse::error("dht query timed out"));
            } else {
                i += 1;
            }
        }
    }

    // ---- RPC dispatch -------------------------------------------------

    /// Dispatches one control request.
    fn dispatch(&mut self, request: RpcRequest) -> Dispatched {
        match request {
            RpcRequest::Status => {
                let data = json!({
                    "peer_id": self.peer_id().to_string(),
                    "tip": hex(self.chain.tip_hash().as_bytes()),
                    "height": self.chain.height(),
                    "peers": self.peers.len(),
                    "domain_count": self.chain.state().len(),
                    "mempool": self.mempool.len(),
                });
                Dispatched::Now(RpcResponse::ok(data))
            }
            RpcRequest::SubmitTx { tx_hex } => Dispatched::Now(match self.submit_tx_hex(&tx_hex) {
                Ok(txid) => RpcResponse::ok(json!({ "txid": txid })),
                Err(e) => RpcResponse::error(e.to_string()),
            }),
            RpcRequest::Lookup { name } => Dispatched::Now(match self.lookup(&name) {
                Ok(data) => RpcResponse::ok(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }),
            RpcRequest::PutRecord { record_hex } => {
                Dispatched::Now(match self.put_record_hex(&record_hex) {
                    Ok(domain_id) => RpcResponse::ok(json!({ "published": domain_id })),
                    Err(e) => RpcResponse::error(e.to_string()),
                })
            }
            // DHT lookups resolve asynchronously through kad events:
            // the waiter is parked; the run loop replies when it
            // resolves (or when its deadline expires).
            RpcRequest::GetRecord { name } => {
                // M5: hard cap on parked waiters — a local RPC client
                // cannot accumulate unbounded 30 s lookups.
                if self.dht_waiters.len() >= MAX_DHT_WAITERS {
                    return Dispatched::Now(RpcResponse::error(format!(
                        "too many concurrent dht lookups (max {MAX_DHT_WAITERS})"
                    )));
                }
                match self.start_dht_get(&name) {
                    Ok(waiter) => Dispatched::Dht(waiter),
                    Err(e) => Dispatched::Now(RpcResponse::error(e.to_string())),
                }
            }
            RpcRequest::DomainInfo { name } => Dispatched::Now(match self.domain_info(&name) {
                Ok(data) => RpcResponse::ok(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }),
            RpcRequest::ResolveLocal { name } => Dispatched::Now(match self.resolve_local(&name) {
                Ok(data) => RpcResponse::ok(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }),
        }
    }

    /// `submit_tx`: decode (bounded), validate, mempool, broadcast.
    fn submit_tx_hex(&mut self, tx_hex: &str) -> Result<String> {
        let bytes = hex_decode(tx_hex)?;
        if bytes.len() > scone_protocol::limits::MAX_MESSAGE_LEN {
            return Err(NetworkError::LimitExceeded("transaction size"));
        }
        let tx: Transaction = decode_complete(&bytes)?;
        let id = self.accept_transaction(tx, None)?;
        Ok(hex(id.as_bytes()))
    }

    /// `lookup`: on-chain state of a domain name.
    fn lookup(&self, name: &str) -> Result<Value> {
        let domain = DomainName::new(name).map_err(|e| NetworkError::Blockchain(e.into()))?;
        let id = DomainId::from_name(&domain);
        match self.chain.state().domain(&id) {
            Some(state) => Ok(json!({
                "name": domain.canonical(),
                "domain_id": hex(id.as_bytes()),
                "registered": true,
                "owner": hex(state.owner.as_bytes()),
                "sequence": state.sequence,
                "record_hash": state.record_hash.map(|h| hex(h.as_bytes())),
            })),
            None => Ok(json!({
                "name": domain.canonical(),
                "domain_id": hex(id.as_bytes()),
                "registered": false,
            })),
        }
    }

    /// `put_record`: decode, verify against the chain, publish in the
    /// DHT (local store + replication to closest peers).
    fn put_record_hex(&mut self, record_hex: &str) -> Result<String> {
        let bytes = hex_decode(record_hex)?;
        if bytes.len() > scone_storage::MAX_DHT_CACHE_ENTRY {
            return Err(NetworkError::LimitExceeded("record size"));
        }
        let record: SignedDnsRecord = decode_complete(&bytes)?;
        if !self.verify_record_against_chain(&record)? {
            return Err(NetworkError::RecordRejected(
                "record does not match the current chain state".into(),
            ));
        }
        let encoded = encode_to_vec(&record)?;
        let key = kad::RecordKey::new(&record.record.domain_id.as_bytes());
        let libp2p_record = kad::Record::new(key, encoded.clone());
        self.swarm
            .behaviour_mut()
            .kad
            // Quorum::Majority of the replication factor: a single
            // targeted peer is not enough to claim the record
            // published (audit H1 — Quorum::One made replication easy
            // to poison/skip).
            .put_record(libp2p_record, kad::Quorum::Majority)
            .map_err(|e| NetworkError::Dht(format!("put: {e}")))?;
        // Also cache in the persistent store (availability on
        // restart).
        self.store
            .put_dht_cache(record.record.domain_id, &encoded)?;
        Ok(record.record.domain_id.to_string())
    }

    /// `get_record`: start a Kademlia lookup and return the waiter
    /// bound to that query and that domain (H1). `handle_kad`
    /// resolves the waiter — and only that waiter — when the query
    /// progresses, after checking the record key against the
    /// requested domain.
    fn start_dht_get(&mut self, name: &str) -> Result<DhtWaiter> {
        let domain = DomainName::new(name).map_err(|e| NetworkError::InvalidRpc(e.to_string()))?;
        let id = DomainId::from_name(&domain);
        let key = kad::RecordKey::new(&id.as_bytes());
        let query = self.swarm.behaviour_mut().kad.get_record(key);
        Ok(DhtWaiter::fresh(query, id))
    }

    /// `domain_info` (M5): rich read-only exploration of one domain.
    ///
    /// On-chain part: registered, owner, sequence, record_hash
    /// (same fields as `lookup`). DNS part: served from the LOCAL
    /// persistent DHT cache only (no network query, no waiter), and
    /// only after full verification against the chain state — an
    /// unregistered domain, a stale/foreign cached record or a hash
    /// mismatch yields `dns: []` (availability is never authority).
    fn domain_info(&self, name: &str) -> Result<Value> {
        let domain = DomainName::new(name).map_err(|e| NetworkError::Blockchain(e.into()))?;
        let id = DomainId::from_name(&domain);
        let Some(state) = self.chain.state().domain(&id) else {
            return Ok(json!({
                "name": domain.canonical(),
                "domain_id": hex(id.as_bytes()),
                "registered": false,
                "dns": [],
            }));
        };
        // Local cache only: if this node has (replicated) the record,
        // decode and verify it; anything short of a fully valid match
        // silently degrades to "no DNS data known locally".
        let dns = match self.store.dht_cache(&id)? {
            Some(bytes) => match decode_complete::<SignedDnsRecord>(&bytes) {
                Ok(record) if self.verify_record_against_chain(&record)? => {
                    json_record_data(&record)
                }
                _ => Vec::new(),
            },
            None => Vec::new(),
        };
        Ok(json!({
            "name": domain.canonical(),
            "domain_id": hex(id.as_bytes()),
            "registered": true,
            "owner": hex(state.owner.as_bytes()),
            "sequence": state.sequence,
            "record_hash": state.record_hash.map(|h| hex(h.as_bytes())),
            "dns": dns,
        }))
    }

    // ---- DNS (M6) ------------------------------------------------------

    /// `resolve_local`: the DNS server's one-round-trip verified
    /// resolution. Shape: `{registered, owner, sequence, dns}` where
    /// `dns` is one `{type, ttl, rdata_hex}` object per record — the
    /// DNS module owns the wire encoding, this owns the verification.
    /// An unregistered domain answers `registered: false`; a
    /// registered one without a chain-valid cached record answers
    /// `dns: []` (NODATA) — availability is never authority.
    fn resolve_local(&self, name: &str) -> Result<Value> {
        let domain = DomainName::new(name).map_err(|e| NetworkError::Blockchain(e.into()))?;
        let id = DomainId::from_name(&domain);
        let Some(state) = self.chain.state().domain(&id) else {
            return Ok(json!({
                "name": domain.canonical(),
                "registered": false,
                "dns": [],
            }));
        };
        let dns = match self.store.dht_cache(&id)? {
            Some(bytes) => match decode_complete::<SignedDnsRecord>(&bytes) {
                Ok(record) if self.verify_record_against_chain(&record)? => record
                    .record
                    .records
                    .iter()
                    .filter_map(crate::dns::encode_rdata_pub)
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            },
            None => Vec::new(),
        };
        Ok(json!({
            "name": domain.canonical(),
            "registered": true,
            "owner": hex(state.owner.as_bytes()),
            "sequence": state.sequence,
            "dns": dns,
        }))
    }

    // ---- P2P ----------------------------------------------------------

    /// Handles one swarm event.
    fn handle_swarm_event(&mut self, event: SwarmEvent<SconeBehaviourEvent>) -> Result<()> {
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

    /// Kademlia events: resolve pending `get_record` waiters.
    ///
    /// H1 hardening: a waiter is only ever resolved by the progress of
    /// **its own** query, and only if the found record's key is the
    /// exact `DomainId` that was requested — checked **before** any
    /// on-chain verification. Cross-talk between concurrent lookups
    /// and key-mismatch poisoning (`SignedDnsRecord` of domain B
    /// stored under domain A's key) both land in the `else` branches.
    fn handle_kad(&mut self, event: kad::Event) {
        if std::env::var_os("SCONE_KAD_DEBUG").is_some() {
            debug!(peer = %self.peer_id(), ?event, "kad event");
        }
        let (query_id, result) = match event {
            kad::Event::OutboundQueryProgressed { id, result, .. } => (id, result),
            _ => return,
        };
        // Is any waiter actually waiting on this query? (A query whose
        // RPC client hung up, or an unrelated kad query, resolves
        // nothing.)
        let Some(position) = self.dht_waiters.iter().position(|w| w.id == query_id) else {
            return;
        };
        match result {
            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(found))) => {
                let waiter = self.dht_waiters.swap_remove(position);
                // Key check BEFORE on-chain verification (H1): the
                // record must live under the requested domain's key.
                if found.record.key.as_ref() != waiter.domain_id.as_bytes().as_slice() {
                    warn!(?query_id, "dht answer key mismatch — dropped");
                    waiter.send(RpcResponse::error(
                        "resolved record key does not match the requested domain",
                    ));
                    return;
                }
                let answer: RpcResponse =
                    match decode_complete::<SignedDnsRecord>(&found.record.value) {
                        Ok(record) => {
                            if self.verify_record_against_chain(&record).unwrap_or(false) {
                                // M5: a chain-verified resolution is cached in
                                // the persistent store, so `domain_info`
                                // (local read) serves it afterwards without
                                // hitting the DHT again.
                                let _ = self
                                    .store
                                    .put_dht_cache(waiter.domain_id, &found.record.value);
                                RpcResponse::ok(json!({
                                    "record": hex(&found.record.value),
                                    "verified": true,
                                }))
                            } else {
                                RpcResponse::error("resolved record does not match chain state")
                            }
                        }
                        Err(e) => RpcResponse::error(format!("bad record bytes: {e}")),
                    };
                waiter.send(answer);
            }
            kad::QueryResult::GetRecord(Err(
                kad::GetRecordError::NotFound { .. } | kad::GetRecordError::Timeout { .. },
            )) => {
                let waiter = self.dht_waiters.swap_remove(position);
                waiter.send(RpcResponse::error("record not found"));
            }
            _ => {}
        }
    }

    // ---- Chain paths ---------------------------------------------------

    /// Full acceptance path of a block (P2P or self-produced):
    /// validate → store → broadcast → reconcile mempool.
    ///
    /// H2 (explicit): a duplicate of an already-canonical block is
    /// detected **before** `push_block` (which would incidentally
    /// reject it via `ParentNotTip`) and answered as a no-op — the
    /// block is NOT re-broadcast, mirroring the transaction rule.
    /// Hashes are recomputed, never taken from the wire.
    fn accept_block(&mut self, block: Block, from: Option<PeerId>) -> Result<BlockHash> {
        let hash = block_hash(&block.header)?;
        if block.header.height <= self.chain.height()
            && self
                .chain
                .block(block.header.height)
                .is_some_and(|canonical| block_hash(&canonical.header) == Ok(hash))
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
            if let Ok(id) = transaction_id(tx) {
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
    fn accept_transaction(&mut self, tx: Transaction, from: Option<PeerId>) -> Result<TxId> {
        scone_blockchain::validate_transaction(&tx)?;
        self.precheck_state(&tx).map_err(NetworkError::Blockchain)?;
        let id = transaction_id(&tx)?;
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
    fn precheck_state(
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
    fn produce_if_ready(&mut self) -> Result<()> {
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

    /// Verifies a DHT record against the chain: owner match, sequence
    /// match and record-hash commitment. `false` (not an error) when
    /// the record does not correspond to the current state.
    fn verify_record_against_chain(&self, record: &SignedDnsRecord) -> Result<bool> {
        let state = match self.chain.state().domain(&record.record.domain_id) {
            Some(state) => state,
            None => return Ok(false),
        };
        if state.owner != record.owner {
            return Ok(false);
        }
        if state.sequence != record.record.sequence {
            return Ok(false);
        }
        match state.record_hash {
            Some(expected) => Ok(expected == scone_protocol::record_hash(&record.record)),
            None => Ok(false),
        }
    }
}

/// Lowercase hex of raw bytes.
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Strict lowercase-hex decode used by the DNS resolver closure.
fn decode_hex_static(text: &str) -> std::result::Result<Vec<u8>, ()> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(());
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| ()))
        .collect()
}

/// Renders the record set of a [`SignedDnsRecord`] as one JSON object
/// per DNS record (`domain_info`, M5). Human-oriented values (IPs,
/// names, text); unknown types expose their raw type code and hex
/// data. Bounded by `MAX_RECORDS_PER_SET` at decode time.
fn json_record_data(record: &SignedDnsRecord) -> Vec<Value> {
    use scone_core::RecordData;
    record
        .record
        .records
        .iter()
        .map(|r| match r {
            RecordData::A(ip) => json!({ "type": "A", "value": ip.to_string() }),
            RecordData::Aaaa(ip) => json!({ "type": "AAAA", "value": ip.to_string() }),
            RecordData::Cname(n) => json!({ "type": "CNAME", "value": n.canonical() }),
            RecordData::Mx {
                preference,
                exchange,
            } => {
                json!({ "type": "MX", "preference": preference, "value": exchange.canonical() })
            }
            RecordData::Txt(t) => json!({ "type": "TXT", "value": t }),
            RecordData::Ns(n) => json!({ "type": "NS", "value": n.canonical() }),
            RecordData::Unknown { type_code, data } => json!({
                "type": format!("TYPE{type_code}"),
                "value": hex(data),
            }),
        })
        .collect()
}

/// Strict hex decode (bounded by the caller).
fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetworkError::InvalidRpc("bad hex".into()));
    }
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| NetworkError::InvalidRpc("bad hex".into()))
        })
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_helpers_roundtrip() {
        assert_eq!(hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_decode("DEAD").unwrap(), vec![0xde, 0xad]);
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("").unwrap().is_empty());
    }
}
