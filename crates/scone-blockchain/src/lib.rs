//! # scone-blockchain
//!
//! Blockchain logic and authoritative state of Scone.
//!
//! Stack:
//!
//! ```text
//! scone-crypto -> scone-core -> scone-protocol -> scone-blockchain
//! ```
//!
//! Responsibilities:
//!
//! - transaction identity ([`TxId`], [`transaction_id`]);
//! - ordered commitment over a block's transactions
//!   ([`merkle_root`], [`tx_root`]);
//! - block identity ([`block_hash`]);
//! - deterministic genesis ([`genesis`], [`genesis_hash`]);
//! - in-memory canonical state and application rules
//!   ([`ChainState`], [`DomainState`]);
//! - chain validation and minimal fork detection ([`Blockchain`]);
//! - a minimal consensus abstraction ([`Consensus`]).
//!
//! Hard rules for this crate:
//!
//! - no networking, no libp2p, no Kademlia/DHT, no DNS server;
//! - no storage backend: the state lives in memory only;
//! - every function validates untrusted data without ever panicking;
//! - provided hashes (`tx_root`, …) are never trusted: they are always
//!   recomputed.
//!
//! Identity chain (see `/docs/technical/blockchain.md`):
//!
//! ```text
//! DomainId -> RegisterDomain/UpdateDomain -> Transaction -> TxId -> MerkleRoot
//!          -> BlockHeader -> BlockHash -> prev_hash -> chain
//! ```
//!
//! Voluntarily deferred to the consensus step: PoW/RandomX, difficulty,
//! fork choice, mempool, global ordering, timestamp authority.

pub mod block_hash;
pub mod builder;
pub mod chain;
pub mod consensus;
pub mod error;
pub mod genesis;
pub mod merkle;
pub mod state;
pub mod txid;
pub mod validate;

pub use block_hash::{BLOCK_HASH_VERSION, block_hash};
pub use builder::BlockBuilder;
pub use chain::Blockchain;
pub use consensus::{Consensus, PermissiveConsensus};
pub use error::{BlockchainError, Result};
pub use genesis::{GENESIS_TIMESTAMP, genesis, genesis_hash};
pub use merkle::{MERKLE_VERSION, merkle_root, tx_root};
pub use state::{ChainState, DomainState, TldState};
pub use txid::{TX_ID_VERSION, TxId, transaction_id};
pub use validate::{owner_from_public_key, validate_transaction};
