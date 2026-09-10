//! # scone-storage
//!
//! Local storage abstraction for Scone nodes.
//!
//! **Nothing is implemented yet.** The concrete backend will be `redb`
//! (embedded key-value store) hidden behind a small trait, so that
//! blockchain state, DHT cache and indexes never couple directly to redb;
//! another backend (e.g. a distributed KV) could be swapped in later.
//!
//! Planned storages (see `/docs/architecture.md`):
//!
//! - blockchain state: `domain_id -> (owner, sequence, record_hash)`
//! - DHT record cache: `domain_id -> SignedDnsRecord`
//! - secondary indexes
//!
//! The `Storage` trait will be introduced together with the first real
//! backend: defining it now, with zero implementations, would be dead
//! abstraction.
