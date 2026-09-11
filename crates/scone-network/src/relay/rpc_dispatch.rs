//! Local control-RPC dispatch: the handlers behind `submit_tx`,
//! `lookup`, `put_record`, `get_record`, `domain_info` and
//! `resolve_local`, plus the parked-DHT-waiter lifecycle (deadline
//! computation, expiry, Kademlia resolution).
//!
//! Extracted verbatim from `relay.rs` (pass 2 refactor); dispatch is
//! fully synchronous — DHT queries park their waiters and resolve
//! through kad events, so the swarm keeps being polled during
//! lookups.

use libp2p::kad;
use serde_json::{Value, json};
use tracing::{debug, warn};

use scone_core::{DomainId, DomainName, SignedDnsRecord, Transaction};
use scone_protocol::decode_complete;
use scone_storage::NodeStore;

use crate::config::MAX_DHT_WAITERS;
use crate::error::{NetworkError, Result};
use crate::rpc::{RpcRequest, RpcResponse};

use super::Relay;
use super::hex::{hex, hex_decode};
use super::task::{DhtWaiter, Dispatched};

impl Relay {
    /// Dispatches one control request.
    pub(super) fn dispatch(&mut self, request: RpcRequest) -> Dispatched {
        match request {
            RpcRequest::Status => {
                let data = json!({
                    "peer_id": self.peer_id().to_string(),
                    "network": self.chain.network().network_id.to_string(),
                    "tip": hex(self.chain.tip_hash().as_bytes()),
                    "height": self.chain.height(),
                    "peers": self.peers.len(),
                    "domain_count": self.chain.state().len(),
                    "mempool": self.mempool.len(),
                    "checkpoints": self.chain.checkpoint_window().len(),
                    "finalized_epoch": self.chain.finalized().map(|f| f.checkpoint.data.epoch),
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
        let encoded = scone_protocol::encode_to_vec(&record)?;
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

    /// Earliest deadline of the parked DHT waiters, if any.
    pub(super) fn next_dht_deadline(&self) -> Option<tokio::time::Instant> {
        self.dht_waiters.iter().map(DhtWaiter::deadline).min()
    }

    /// Fails every waiter whose deadline has passed.
    pub(super) fn expire_stale_dht_waiters(&mut self) {
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

    /// Kademlia events: resolve pending `get_record` waiters.
    ///
    /// H1 hardening: a waiter is only ever resolved by the progress of
    /// **its own** query, and only if the found record's key is the
    /// exact `DomainId` that was requested — checked **before** any
    /// on-chain verification. Cross-talk between concurrent lookups
    /// and key-mismatch poisoning (`SignedDnsRecord` of domain B
    /// stored under domain A's key) both land in the `else` branches.
    pub(super) fn handle_kad(&mut self, event: kad::Event) {
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

    /// Verifies a DHT record against the chain: owner match, sequence
    /// match and record-hash commitment. `false` (not an error) when
    /// the record does not correspond to the current state.
    pub(super) fn verify_record_against_chain(&self, record: &SignedDnsRecord) -> Result<bool> {
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
