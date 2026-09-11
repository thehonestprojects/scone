//! # scone-network
//!
//! P2P relay of Scone (milestone M4): a libp2p node that relays
//! transactions and blocks, validates everything locally, keeps the
//! canonical chain in RAM backed by a [`NodeStore`], serves a bounded
//! block-sync protocol, publishes and resolves signed DNS records in a
//! Kademlia DHT, and exposes a local JSON control-RPC on 127.0.0.1
//! (the surface the `scone` CLI talks to).
//!
//! Stack:
//!
//! ```text
//! crypto -> core -> protocol -> blockchain -> storage -> network
//! ```
//!
//! ## Hard rules of this crate
//!
//! - **every network input is untrusted**: frames are size-bounded
//!   before parsing ([`scone_protocol::limits::MAX_MESSAGE_LEN`]),
//!   decoding is strict, nothing ever panics on remote data;
//! - **memory is bounded**: the mempool has a fixed capacity, sync
//!   responses carry at most `MAX_BLOCKS_PER_RESPONSE` blocks, chain
//!   data is loaded from the store with paged reads;
//! - **the chain stays the authority**: every received block/tx runs
//!   through the full existing validation (`Blockchain::push_block`,
//!   `validate_transaction`) before any state change; DHT data is
//!   never trusted until verified against the chain;
//! - **isolated async surface**: this is the only async crate of the
//!   workspace; everything below it stays synchronous and pure.

pub mod behaviour;
pub mod config;
pub mod dns;
pub mod error;
pub mod mempool;
pub mod relay;
pub mod rpc;
pub mod sync;

pub use behaviour::{SconeCodec, SconeProtocol};
pub use config::{
    Config, DEFAULT_MEMPOOL_CAPACITY, DEFAULT_PRODUCE_INTERVAL, MAX_DHT_WAITERS,
    MAX_RPC_CONNECTIONS,
};
pub use dns::{ANSWER_TTL, Cache, CacheEntry, MAX_INFLIGHT_UDP, MAX_PACKET_LEN, Resolved};
pub use error::{NetworkError, Result};
pub use mempool::{MAX_PENDING_PER_DOMAIN, Mempool, domain_key};
pub use relay::Relay;
pub use rpc::{RpcClient, RpcRequest, RpcResponse};
pub use sync::MAX_BLOCKS_PER_RESPONSE;
