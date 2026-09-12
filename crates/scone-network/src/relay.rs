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
//!
//! ## Module map (pass 2 refactor)
//!
//! - [`task`]: shared plumbing — `RelayCommand`, `Dispatched`,
//!   `DhtWaiter`, `SyncState`;
//! - [`hex`]: strict lowercase-hex helpers (and their tests);
//! - `swarm`: swarm/peer events, protocol messages, sync driver;
//! - `chain`: block/transaction acceptance paths and devnet
//!   production;
//! - `rpc_dispatch`: control-RPC handlers and DHT waiter lifecycle.

mod anchor;
mod chain;
mod hex;
mod rpc_dispatch;
mod swarm;
mod task;

pub use swarm::MAX_SYNC_ROUNDS;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::channel::mpsc;
use futures::prelude::*;
use libp2p::swarm::SwarmEvent;
use libp2p::{PeerId, Swarm};
use scone_blockchain::Blockchain;
use scone_storage::{RedbStore, integration as store_integration};
use tokio::sync::oneshot;
use tracing::{info, warn};

use self::task::{DhtWaiter, Dispatched, RelayCommand, SyncState};
use crate::behaviour::{
    SconeBehaviour, SconeBehaviourEvent, build_behaviour, parse_bootstrap_addr,
};
use crate::config::{Config, MAX_RPC_CONNECTIONS};
use crate::error::{NetworkError, Result};
use crate::mempool::Mempool;
use crate::rpc::{self, RpcResponse};

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
    /// Anchor loop state (checkpoint signing + aggregation). Always
    /// present; holds signing material only when an anchor keyfile is
    /// configured.
    anchor: self::anchor::AnchorLoop,
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
        let chain = store_integration::load_chain(&store, config.network)?;
        // M8b: the relay's network and the store's chain must agree —
        // a data directory is per-network by construction (the CLI
        // enforces it); mixing them is a local misconfiguration, not
        // untrusted input.
        if chain.network().network_id != config.network.network_id {
            let found = chain.network().network_id;
            let wanted = config.network.network_id;
            return Err(NetworkError::Peer(format!(
                "data directory holds a '{found}' chain but this relay runs '{wanted}' — use a per-network data directory"
            )));
        }
        let mempool = Mempool::new(config.mempool_capacity);
        let rpc_addr = config.rpc_addr;

        // The anchor key is read BEFORE `config` is moved into the
        // relay: a bad keyfile/passphrase is a startup error the
        // operator must see (the relay then runs unarmed if the
        // caller chooses to continue without it).
        let anchor_config = config.clone();

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
            anchor: self::anchor::AnchorLoop::load(&anchor_config)?,
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

        // ---- UDP + TCP DNS surface (M6/M7b), optional --------------
        // The DNS server talks to the relay core through the same
        // local RPC as the CLI (`ResolveLocal`: one round trip,
        // verified, no parked DHT waiter) — the verified path stays
        // single and identical for every consumer. TCP (RFC 7766)
        // shares the UDP port: answers cut at 512 B over UDP (TC=1)
        // are served in full over TCP.
        let dns_task: Option<tokio::task::JoinHandle<()>> = match self.config.dns_addr {
            Some(dns_addr) => {
                let upstreams = crate::dns::parse_upstreams(&self.config.dns_upstreams)?;
                let socket = Arc::new(tokio::net::UdpSocket::bind(dns_addr).await?);
                let dns_listen = socket.local_addr()?;
                // Same address, TCP: a second bind on the port the
                // UDP socket just took (best-effort — a failure is
                // logged and the UDP surface keeps serving).
                let tcp_listener = match tokio::net::TcpListener::bind(dns_listen).await {
                    Ok(l) => Some(l),
                    Err(e) => {
                        warn!(%dns_listen, "dns tcp bind failed (udp only): {e}");
                        None
                    }
                };
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
                let cache = Arc::new(tokio::sync::Mutex::new(crate::dns::Cache::with_bounds(
                    self.config.dns_cache_capacity,
                    crate::dns::MAX_FALLBACK_TTL,
                )));
                let tcp_resolver = resolver.clone();
                let tcp_upstreams = upstreams.clone();
                let tcp_cache = cache.clone();
                if let Some(listener) = tcp_listener {
                    tokio::spawn(async move {
                        if let Err(e) =
                            crate::dns::run_tcp(listener, tcp_resolver, tcp_upstreams, tcp_cache)
                                .await
                        {
                            warn!("dns tcp server ended: {e}");
                        }
                    });
                }
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
