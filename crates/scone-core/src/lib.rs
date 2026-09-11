//! # scone-core
//!
//! Foundation types of the Scone protocol: names, identities, DNS records
//! and transactions.
//!
//! Hard rules for this crate:
//!
//! - no networking, no filesystem, no OS, no async/tokio
//! - no libp2p, no redb, no DNS server, no blockchain logic
//! - deterministic, portable, strongly-typed validation only
//!
//! Concrete cryptography lives in `scone-crypto`; the core only calls it
//! for hashing.

pub mod error;
pub mod id;
pub mod name;
pub mod owner;
pub mod record;
pub mod transaction;

pub use error::{Result, SconeError};
pub use id::{DomainId, TldId};
pub use name::{DomainName, TldName};
pub use owner::{OwnerId, PublicKeyRef};
pub use record::{DnsRecord, RecordData, Signature, SignedDnsRecord};
pub use transaction::{Proof, RecordHash, RegisterDomain, RegisterTld, Transaction, UpdateDomain};
