//! # scone-protocol
//!
//! Binary wire and blockchain format of the Scone protocol: how the
//! objects of [`scone-core`] are represented and exchanged as bytes
//! (transactions, DNS records, blocks, P2P messages). Reference format
//! documentation: `/docs/technical/protocol.md`.
//!
//! This crate contains **no** consensus, chain-selection, storage,
//! Kademlia, transport or DNS logic — only formats, limits and encoding
//! rules, so that `scone-blockchain`, `scone-dht`, `scone-network` and
//! `scone-dns` all speak exactly the same protocol.
//!
//! Stack:
//!
//! ```text
//! scone-crypto -> scone-core -> scone-protocol -> blockchain/DHT/network/DNS
//! ```
//!
//! ## Encoding rules
//!
//! - all integers are minimal LEB128 varints ([`varint`]); overlong
//!   forms are rejected on decode;
//! - fixed-size identifiers (`DomainId`, `OwnerId`, `RecordHash`,
//!   `BlockHash`, ...) are 32 raw bytes, no prefix;
//! - byte and UTF-8 strings are varint-length-prefixed and bounded by
//!   the constants in [`limits`], checked **before** any allocation;
//! - the encoding is **canonical**: logically equal objects produce
//!   exactly equal bytes (record sets are sorted strictly increasing,
//!   varints are minimal), so encoded bytes can be hashed and signed
//!   directly:
//!
//! ```text
//! canonical object -> canonical binary encoding -> hash / signature
//! ```
//!
//! - decoding treats every input as untrusted: bounds are checked before
//!   allocation, non-canonical or unknown values are rejected with
//!   [`ProtocolError`], and decoding never panics on network data.

pub mod block;
pub mod codec;
pub mod error;
pub mod hash;
pub mod ids;
pub mod limits;
pub mod message;
pub mod record;
pub mod transaction;
pub mod varint;

pub use block::{Block, BlockHash, BlockHeader, MerkleRoot};
pub use codec::{Decode, Encode, decode_complete, encode_to_vec};
pub use error::{ProtocolError, Result};
pub use hash::record_hash;
pub use message::Message;
pub use transaction::{TX_FORMAT_VERSION, TX_SIG_PREFIX, UnsignedTransaction, signing_payload};

/// Protocol version. Bumped on any breaking wire-format change.
///
/// Compatibility rules (see `/docs/technical/protocol.md`):
///
/// - a version received that is **greater** than the local one (or zero)
///   is rejected with [`ProtocolError::UnsupportedVersion`];
/// - there is no major/minor split yet: one integer, bumped on break.
pub const PROTOCOL_VERSION: u32 = 1;
