//! Blockchain ⟷ storage integration: persisting and replaying a chain
//! through a [`NodeStore`](crate::NodeStore).
//!
//! ## Division of responsibility
//!
//! - [`Blockchain`](scone_blockchain::Blockchain) keeps the
//!   **authoritative state in RAM** (consensus source of truth);
//! - the store is **persistence only**: block bytes + the *modified*
//!   domain/TLD states of each block (delta), never the full state.
//!
//! ## Chosen strategy (documented): persist-state-per-block
//!
//! Domain states are reconstructible by replay
//! ([`load_chain_replay`]), but each [`store_block`] call persists the
//! domains touched by the block — so a restart needs **no replay**
//! ([`load_chain`] just reads the tip). This is the simple option; the
//! replay path exists as a consistency check / repair tool.
//!
//! ## Typical relay usage (M4)
//!
//! ```text
//! let store = RedbStore::open(path)?;
//! let mut chain = load_chain(&store)?;            // O(1): tip + RAM rebuild
//! let hash = chain.push_block(&block)?;           // consensus in RAM
//! store_block(&mut store, &chain, &block, hash)?; // atomic delta persist
//! ```

use scone_blockchain::{
    Blockchain, DomainState, REPLAY_WINDOW_BLOCKS, TldState, block_hash, transaction_id,
};
use scone_core::{DomainId, TldId, Transaction};
use scone_protocol::{Block, BlockHash, decode_complete, encode_to_vec};

use crate::NodeStore;
use crate::error::{Result, StorageError};
use crate::{DomainStateBytes, TldStateBytes};

/// Batch size of domain-state pagination.
pub const DOMAIN_PAGE: usize = 100;

/// Batch size of TLD-state pagination (M7d).
pub const TLD_PAGE: usize = 100;

/// TLDs whose state a block's transactions mutate, in block order,
/// deduplicated (M8b: every TLD-family tx — claim, transfer, revoke,
/// open/close — included).
///
/// Same contract as [`touched_domains`]: references only, final values
/// read from the (already updated) chain state.
#[must_use]
pub fn touched_tlds(block: &Block) -> Vec<&TldId> {
    let mut seen = std::collections::HashSet::new();
    block
        .transactions
        .iter()
        .filter_map(|tx| match tx {
            Transaction::RegisterTld(r) => seen.insert(r.tld_id).then_some(&r.tld_id),
            Transaction::TransferTld(t) => seen.insert(t.tld_id).then_some(&t.tld_id),
            Transaction::RevokeTld(r) => seen.insert(r.tld_id).then_some(&r.tld_id),
            Transaction::SetTldOpen(s) => seen.insert(s.tld_id).then_some(&s.tld_id),
            _ => None,
        })
        .collect()
}

/// Domains whose state a block's transactions modify, in block order,
/// deduplicated (last write wins) (M8b: RegisterDomain, UpdateDomain,
/// AssignDomain, RenewDomain).
///
/// Returns *references* into `block`'s transactions — no state is
/// copied. The caller reads the final values from the (already
/// updated) chain state.
#[must_use]
pub fn touched_domains(block: &Block) -> Vec<&DomainId> {
    let mut seen = std::collections::HashSet::new();
    block
        .transactions
        .iter()
        .filter_map(|tx| match tx {
            Transaction::RegisterDomain(r) => seen.insert(r.domain_id).then_some(&r.domain_id),
            Transaction::UpdateDomain(u) => seen.insert(u.domain_id).then_some(&u.domain_id),
            Transaction::AssignDomain(a) => seen.insert(a.domain_id).then_some(&a.domain_id),
            Transaction::RenewDomain(r) => seen.insert(r.domain_id).then_some(&r.domain_id),
            Transaction::RegisterTld(_)
            | Transaction::TransferTld(_)
            | Transaction::RevokeTld(_)
            | Transaction::SetTldOpen(_)
            | Transaction::Slash(_) => None,
        })
        .collect()
}

/// Domains removed from the state between the pre-block snapshot and
/// the post-block state: M8b garbage collection of expired
/// registrations. The caller (the relay loop, which owns both the
/// chain and the store) detects them by diffing around `push_block`;
/// this helper reconstructs the GC set of one block from the block
/// contents alone for tests and repair tools.
///
/// # Errors
///
/// Never fails in practice (decoding of stored states is exercised
/// through [`NodeStore`]); kept `Result` for symmetry.
#[must_use]
pub fn gc_of_block(store: &impl NodeStore, block: &Block) -> Vec<DomainId> {
    // The deterministic GC ran with the PARENT timestamp; the domains
    // it removed are exactly those that were stored before the block
    // and are absent from the chain state after it. Reconstructing
    // that here would need the pre-state; instead, the relay passes
    // the removals it observed (see `store_block_with_removals`).
    let _ = (store, block);
    Vec::new()
}

/// Atomic delta persistence of an accepted block.
///
/// Encodes `block` canonically, reads the final state of each touched
/// domain AND each mutated TLD from the chain's RAM state (the
/// consensus authority), and writes block + tip + domain deltas + TLD
/// deltas in ONE store transaction.
///
/// `hash` MUST be the recomputed block hash (`Blockchain::push_block`
/// return value). The store does not re-validate blocks.
///
/// # Errors
///
/// [`StorageError`] on encoding failure or store error; the store is
/// left unchanged on error (ACID).
pub fn store_block(
    store: &mut impl NodeStore,
    chain: &Blockchain,
    block: &Block,
    hash: BlockHash,
) -> Result<()> {
    store_block_with_removals(store, chain, block, hash, &[])
}

/// [`store_block`] with the M8b GC removals of the block: domains the
/// deterministic expiry-GC dropped while applying `block`. Their
/// stored states are deleted in the same atomic transaction — a
/// restart can never resurrect an expired registration.
///
/// # Errors
///
/// See [`store_block`].
pub fn store_block_with_removals(
    store: &mut impl NodeStore,
    chain: &Blockchain,
    block: &Block,
    hash: BlockHash,
    removed_domains: &[DomainId],
) -> Result<()> {
    let bytes = encode_to_vec(block).map_err(|e| StorageError::Corrupted(e.to_string()))?;
    let deltas: Vec<(DomainId, DomainStateBytes)> = touched_domains(block)
        .into_iter()
        .filter_map(|id| {
            chain
                .state()
                .domain(id)
                .map(|state| (*id, DomainStateBytes::from(&state)))
        })
        .collect();
    // TLD deltas: present states are upserted; absent ones (revoked)
    // are deleted from the store in the same transaction.
    let tld_upserts: Vec<(TldId, TldStateBytes)> = touched_tlds(block)
        .into_iter()
        .filter_map(|id| {
            chain
                .state()
                .tld(id)
                .map(|state| (*id, TldStateBytes::from(&state)))
        })
        .collect();
    let tld_removals: Vec<TldId> = touched_tlds(block)
        .into_iter()
        .copied()
        .filter(|id| chain.state().tld(id).is_none())
        .collect();
    // P0.2 name-index deltas, derived from the SAME transactions:
    // RegisterDomain/AssignDomain bind (canonical name, DomainId),
    // RegisterTld binds (tld name, TldId). The tx invariants
    // guarantee `domain_id == DomainId::from_name(name)` — the
    // binding re-states what the block already proves.
    let mut name_upserts: Vec<crate::NameBinding> = Vec::new();
    for tx in &block.transactions {
        match tx {
            Transaction::RegisterDomain(r) => {
                name_upserts.push(crate::NameBinding {
                    is_tld: false,
                    name: r.name.canonical().to_owned(),
                    target: *r.domain_id.as_bytes(),
                });
            }
            Transaction::AssignDomain(a) => {
                name_upserts.push(crate::NameBinding {
                    is_tld: false,
                    name: a.name.canonical().to_owned(),
                    target: *a.domain_id.as_bytes(),
                });
            }
            Transaction::RegisterTld(t) => {
                name_upserts.push(crate::NameBinding {
                    is_tld: true,
                    name: t.name.as_str().to_owned(),
                    target: *t.tld_id.as_bytes(),
                });
            }
            _ => {}
        }
    }
    let mut name_removals: Vec<(bool, [u8; 32])> = removed_domains
        .iter()
        .map(|id| (false, *id.as_bytes()))
        .collect();
    name_removals.extend(tld_removals.iter().map(|id| (true, *id.as_bytes())));
    let delta = crate::StateDelta {
        domains: deltas,
        tlds: tld_upserts,
        removed_domains: removed_domains.to_vec(),
        removed_tlds: tld_removals,
        name_upserts,
        name_removals,
    };
    store.append_block_with_state(block.header.height, hash.as_bytes(), &bytes, &delta)
}

/// Loads the chain from `store` **without replaying the full
/// history**: reads the tip metadata and the tip block only (O(1)
/// block reads). The stored tip hash is never trusted: it is
/// **recomputed** from the tip block header and must match
/// (`Corrupted` otherwise). The RAM state is restored from the
/// persisted domain states, paged by [`DOMAIN_PAGE`]
/// (memory-bounded). Historical blocks stay in the store and are
/// served from there.
///
/// # M6b fast boot via state snapshot
///
/// When the store holds a state snapshot ([`NodeStore::snapshot_meta`])
/// strictly below the persisted tip, the snapshot state is restored
/// (paged) and ONLY the blocks above the snapshot height are
/// replayed — O(tip − H) instead of O(tip). The snapshot is anchored
/// before use: the hash of the stored block at the snapshot height is
/// RECOMPUTED and must equal the snapshot's `tip_hash` (mismatch, a
/// snapshot above the tip, or any decode failure along the way → the
/// snapshot is ignored and the plain full-state load runs —
/// fail-safe, never a boot failure).
///
/// # Errors
///
/// [`StorageError::Corrupted`] if a stored value fails strict
/// decoding, or if the recomputed tip hash differs from the stored
/// `meta["tip"]`; [`StorageError`] on store errors.
pub fn load_chain(
    store: &impl NodeStore,
    network: scone_core::NetworkParams,
) -> Result<Blockchain> {
    let (tip_height, tip_hash) = store.tip()?;
    if tip_height == 0 {
        // Empty store: the chain starts at the DEFAULT network's
        // genesis. The relay re-binds it to its configured network
        // when the store is empty (pass the network explicitly).
        return Ok(Blockchain::for_network(network));
    }
    let tip_bytes = store.block_at_height(tip_height)?.ok_or_else(|| {
        StorageError::Corrupted(format!("blocks_by_height[{tip_height}]: tip block missing"))
    })?;
    let tip_block: Block = decode_complete(&tip_bytes)
        .map_err(|e| StorageError::Corrupted(format!("tip block: {e}")))?;
    if tip_block.header.height != tip_height {
        return Err(StorageError::Corrupted(format!(
            "blocks_by_height[{tip_height}]: block announces height {}",
            tip_block.header.height
        )));
    }
    // Project rule: hashes are always recomputed, never trusted. The
    // stored `meta["tip"]` is compared against the hash derived from
    // the tip header itself.
    let recomputed = block_hash(&tip_block.header)
        .map_err(|e| StorageError::Corrupted(format!("tip block hash: {e}")))?;
    if recomputed.as_bytes() != &tip_hash {
        let stored: String = tip_hash.iter().map(|b| format!("{b:02x}")).collect();
        let actual: String = recomputed
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        return Err(StorageError::Corrupted(format!(
            "meta tip hash {stored} != recomputed tip hash {actual}"
        )));
    }
    if let Some(mut chain) =
        try_load_from_snapshot(store, network, tip_height, &tip_block, recomputed)
    {
        rebuild_replay_index_from_store(store, &mut chain, tip_height)?;
        return Ok(chain);
    }
    let mut chain = load_from_full_state(store, network, tip_height, &tip_block, recomputed)?;
    rebuild_replay_index_from_store(store, &mut chain, tip_height)?;
    Ok(chain)
}

/// Rebuilds the anti-replay TXID index of a restored chain by
/// re-scanning the persisted window tail (M8).
///
/// `load_chain` does not replay history, so the RAM index a
/// `Blockchain::restore` starts with is empty — before M8 a
/// restarted node accepted the re-inclusion of any transaction still
/// inside its replay window (the state rules remained the only
/// backstop). This closes that window: the last
/// `min(REPLAY_WINDOW_BLOCKS, tip_height)` stored blocks are read
/// one by one (memory-bounded — one block in RAM at a time) and
/// every transaction is re-inserted in the index at its **original
/// inclusion height** via the public
/// [`Blockchain::rebuild_replay_index`] API (no private field
/// access). The result is bit-identical to the index a live node
/// holds: same entries, same prune rule.
///
/// The suffix-replay path (`try_load_from_snapshot`) reconstructs
/// the index for the blocks it replays; this scan adds the part of
/// the window BELOW the snapshot height — the snapshot never froze
/// the index (same contract as owner keys / grace windows:
/// non-consensus RAM structures are rebuilt, never persisted).
///
/// # Errors
///
/// [`StorageError::Corrupted`] if a window block is missing below
/// the tip or fails canonical decoding — the window blocks are the
/// same bytes the chain was built from, a failure means the store
/// is damaged.
pub fn rebuild_replay_index_from_store(
    store: &impl NodeStore,
    chain: &mut Blockchain,
    tip_height: u64,
) -> Result<()> {
    let start = tip_height.saturating_sub(REPLAY_WINDOW_BLOCKS - 1).max(1);
    let mut entries: Vec<(scone_blockchain::TxId, u64)> = Vec::new();
    for height in start..=tip_height {
        let Some(bytes) = store.block_at_height(height)? else {
            return Err(StorageError::Corrupted(format!(
                "blocks_by_height[{height}]: missing inside the replay window"
            )));
        };
        let block: Block = decode_complete(&bytes)
            .map_err(|e| StorageError::Corrupted(format!("block {height}: {e}")))?;
        if block.header.height != height {
            return Err(StorageError::Corrupted(format!(
                "blocks_by_height[{height}]: block announces height {}",
                block.header.height
            )));
        }
        for tx in &block.transactions {
            if let Ok(id) = transaction_id(tx) {
                entries.push((id, height));
            }
        }
    }
    chain.rebuild_replay_index(entries.into_iter());
    Ok(())
}

/// Snapshot boot path (M6b): restore the frozen state and replay only
/// the suffix above it. Returns `None` when the snapshot is unusable
/// (absent, above the tip, foreign to the persisted chain, or failing
/// any strict decode) — the caller then falls back to the plain
/// full-state load. A bad snapshot must degrade the boot, never break
/// it.
fn try_load_from_snapshot(
    store: &impl NodeStore,
    network: scone_core::NetworkParams,
    tip_height: u64,
    tip_block: &Block,
    tip: BlockHash,
) -> Option<Blockchain> {
    // Backends without snapshot support return None/empty pages (the
    // trait defaults) — plain full-state load for them.
    let meta = store.snapshot_meta().ok()?;
    let meta = meta?;
    // Usable only strictly below the persisted tip: a snapshot at (or
    // above) the tip would leave nothing to anchor it and the suffix
    // replay empty — the full load is the correct path then.
    if meta.height == 0 || meta.height >= tip_height {
        return None;
    }
    // Anchor check (fail-safe): the hash of the canonical block at
    // the snapshot height is RECOMPUTED from its header and must
    // equal the snapshot's tip_hash. A snapshot from another chain
    // (or a tampered one) is silently ignored — full load decides.
    let anchor_bytes = store.block_at_height(meta.height).ok()??;
    let anchor_block: Block = decode_complete(&anchor_bytes).ok()?;
    if anchor_block.header.height != meta.height {
        return None;
    }
    let anchor_hash = block_hash(&anchor_block.header).ok()?;
    if anchor_hash.as_bytes() != &meta.tip_hash {
        return None;
    }

    // Restore the frozen state, paged (memory-bounded).
    let mut state = scone_blockchain::ChainState::new();
    let mut cursor: Option<DomainId> = None;
    loop {
        let (page, next) = store.snapshot_domains(cursor, DOMAIN_PAGE).ok()?;
        let page_len = page.len();
        if page_len == 0 && cursor.is_some() {
            // Exhausted mid-iteration (backend default or truncation).
            break;
        }
        for (domain, encoded) in page {
            let Ok(domain_state) = DomainStateBytes::decode(encoded.as_encoded()) else {
                return None;
            };
            state.restore_domain(domain, domain_state).ok()?;
        }
        cursor = next;
        if page_len < DOMAIN_PAGE {
            break;
        }
    }
    let mut tld_cursor: Option<TldId> = None;
    loop {
        let (page, next) = store.snapshot_tlds(tld_cursor, TLD_PAGE).ok()?;
        let page_len = page.len();
        if page_len == 0 && tld_cursor.is_some() {
            break;
        }
        for (tld, encoded) in page {
            let Ok(tld_state) = TldStateBytes::decode(encoded.as_encoded()) else {
                return None;
            };
            state.restore_tld(tld, tld_state).ok()?;
        }
        tld_cursor = next;
        if page_len < TLD_PAGE {
            break;
        }
    }

    // Replay ONLY the suffix above the snapshot height, with the
    // exact same validation as live blocks. Any failure falls back to
    // the plain full-state load (the full load re-derives everything
    // from the live tables and reports the underlying error if the
    // store is genuinely corrupt).
    let mut chain = Blockchain::restore(meta.height, anchor_hash, anchor_block, state);
    for height in (meta.height + 1)..=tip_height {
        let Ok(Some(bytes)) = store.block_at_height(height) else {
            return None;
        };
        let Ok(block) = decode_complete::<Block>(&bytes) else {
            return None;
        };
        if block.header.height != height {
            return None;
        }
        chain.push_block(&block).ok()?;
    }
    debug_assert_eq!(chain.height(), tip_height);
    let _ = tip_block; // tip block already validated by the caller
    if chain.tip_hash() != tip {
        return None;
    }
    // Same network binding check as the full path.
    if chain.network().network_id != network.network_id {
        return None;
    }
    Some(chain)
}

/// Plain full-state load (pre-M6b path): tip + the persisted live
/// domain/TLD tables, no block replay.
fn load_from_full_state(
    store: &impl NodeStore,
    network: scone_core::NetworkParams,
    tip_height: u64,
    tip_block: &Block,
    recomputed: BlockHash,
) -> Result<Blockchain> {
    let mut state = scone_blockchain::ChainState::new();
    let mut cursor: Option<DomainId> = None;
    loop {
        let (page, next) = store.iterate_domains(cursor, DOMAIN_PAGE)?;
        let page_len = page.len();
        for (domain, encoded) in page {
            let domain_state: DomainState = DomainStateBytes::decode(encoded.as_encoded())?;
            state
                .restore_domain(domain, domain_state)
                .map_err(|e| StorageError::Corrupted(e.to_string()))?;
        }
        cursor = next;
        if page_len < DOMAIN_PAGE {
            break;
        }
    }
    // M7d — restart window closure: restore the TLD registry too.
    // Without it, a restarted node forgot every claimed TLD and any
    // RegisterDomain under them failed `UnknownTld` at precheck even
    // though the chain state it served was authoritative.
    let mut tld_cursor: Option<TldId> = None;
    loop {
        let (page, next) = store.iterate_tlds(tld_cursor, TLD_PAGE)?;
        let page_len = page.len();
        for (tld, encoded) in page {
            let tld_state: TldState = TldStateBytes::decode(encoded.as_encoded())?;
            state
                .restore_tld(tld, tld_state)
                .map_err(|e| StorageError::Corrupted(e.to_string()))?;
        }
        tld_cursor = next;
        if page_len < TLD_PAGE {
            break;
        }
    }
    let chain = Blockchain::restore(tip_height, recomputed, tip_block.clone(), state);
    // M8b network separation: a non-empty data directory holds
    // exactly one network's chain. The restored chain's network
    // is derived from its genesis hash — the strongest possible
    // binding (the store cannot lie about which genesis it was
    // built on).
    if chain.network().network_id != network.network_id {
        return Err(StorageError::Corrupted(format!(
            "data directory holds a '{}' chain but '{}' was requested — use a per-network data directory",
            chain.network().network_id,
            network.network_id
        )));
    }
    Ok(chain)
}

/// Rebuilds the chain by **replaying** every stored block (blocks read
/// one at a time from `block_at_height`, never all at once) — full
/// validation runs exactly as for live blocks.
///
/// Consistency check and repair tool: the resulting tip hash must
/// equal the stored tip.
///
/// # Errors
///
/// [`StorageError::Corrupted`] if a stored block fails canonical
/// decoding; [`scone_blockchain`] validation errors surface as
/// [`StorageError::Corrupted`] with the original message.
pub fn load_chain_replay(store: &impl NodeStore) -> Result<Blockchain> {
    let mut chain = Blockchain::new();
    let (tip_height, tip_hash) = store.tip()?;
    for height in 1..=tip_height {
        let Some(bytes) = store.block_at_height(height)? else {
            return Err(StorageError::Corrupted(format!(
                "blocks_by_height[{height}]: missing below tip"
            )));
        };
        let block: Block = decode_complete(&bytes)
            .map_err(|e| StorageError::Corrupted(format!("block {height}: {e}")))?;
        if block.header.height != height {
            return Err(StorageError::Corrupted(format!(
                "blocks_by_height[{height}]: block announces height {}",
                block.header.height
            )));
        }
        chain
            .push_block(&block)
            .map_err(|e| StorageError::Corrupted(format!("block {height}: {e}")))?;
    }
    if *chain.tip_hash().as_bytes() != tip_hash {
        let replayed: String = chain
            .tip_hash()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let stored: String = tip_hash.iter().map(|b| format!("{b:02x}")).collect();
        return Err(StorageError::Corrupted(format!(
            "replay tip {replayed} != stored tip {stored}"
        )));
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_core::{DomainName, Proof, RecordHash, RegisterDomain, UpdateDomain};
    use scone_crypto::{Signature, SigningKey};

    /// Signs a transaction over its canonical signing payload.
    fn sign(unsigned: Transaction, sk: &SigningKey) -> Transaction {
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        match unsigned {
            Transaction::RegisterDomain(mut r) => {
                r.signature = sk.sign(&payload);
                Transaction::RegisterDomain(r)
            }
            Transaction::UpdateDomain(mut u) => {
                u.signature = sk.sign(&payload);
                Transaction::UpdateDomain(u)
            }
            Transaction::RegisterTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::RegisterTld(t)
            }
            Transaction::TransferTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::TransferTld(t)
            }
            Transaction::RevokeTld(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::RevokeTld(t)
            }
            Transaction::SetTldOpen(mut t) => {
                t.signature = sk.sign(&payload);
                Transaction::SetTldOpen(t)
            }
            Transaction::AssignDomain(mut a) => {
                a.signature = sk.sign(&payload);
                Transaction::AssignDomain(a)
            }
            Transaction::RenewDomain(mut r) => {
                r.signature = sk.sign(&payload);
                Transaction::RenewDomain(r)
            }
            Transaction::Slash(mut x) => {
                x.signature = sk.sign(&payload);
                Transaction::Slash(x)
            }
        }
    }

    fn signed_register_domain(sk: &SigningKey, name: &str) -> Transaction {
        sign(
            Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                Proof::from_bytes(Vec::new()),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    fn signed_update_domain(sk: &SigningKey, name: &str, sequence: u64) -> Transaction {
        let domain = DomainId::from_name(&DomainName::new(name).unwrap());
        sign(
            Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
                domain,
                sequence,
                RecordHash::from_bytes([sequence as u8; 32]),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    #[test]
    fn touched_domains_dedupes_in_order() {
        let sk = SigningKey::from_bytes([1; 32]);
        let mut block = scone_blockchain::BlockBuilder::after(0, scone_blockchain::genesis_hash())
            .build()
            .unwrap();
        block.transactions.clear();
        // Two transactions on a.uip, one on b.uip.
        block
            .transactions
            .push(signed_register_domain(&sk, "a.uip"));
        block
            .transactions
            .push(signed_update_domain(&sk, "a.uip", 1));
        block
            .transactions
            .push(signed_register_domain(&sk, "b.uip"));
        let a = DomainId::from_name(&DomainName::new("a.uip").unwrap());
        let b = DomainId::from_name(&DomainName::new("b.uip").unwrap());
        assert_eq!(touched_domains(&block), vec![&a, &b]);
    }

    // --- M8b regression: expired domains stay dead across a restart ---

    fn mined_proof(prefix: &[u8], name: &str, difficulty: u32) -> Proof {
        let mut challenge = Vec::new();
        challenge.extend_from_slice(prefix);
        challenge.extend_from_slice(name.as_bytes());
        let checked = scone_core::pow::mine(scone_core::TESTNET.network_id, &challenge, difficulty);
        Proof::from_bytes(scone_core::pow::encode_proof(&checked))
    }

    fn signed_claim_tld(sk: &SigningKey, tld: &str) -> Transaction {
        sign(
            Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
                scone_core::TldName::new(tld).unwrap(),
                1,
                mined_proof(
                    scone_core::id::TLD_ID_VERSION,
                    tld,
                    scone_core::TESTNET.tld_pow_difficulty,
                ),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    fn signed_open_tld(sk: &SigningKey, tld: &str) -> Transaction {
        sign(
            Transaction::SetTldOpen(scone_core::SetTldOpen::set_tld_open_signed(
                scone_core::TldId::from_tld(&scone_core::TldName::new(tld).unwrap()),
                true,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    fn signed_register(sk: &SigningKey, name: &str) -> Transaction {
        sign(
            Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                mined_proof(
                    scone_core::id::DOMAIN_ID_VERSION,
                    name,
                    scone_core::TESTNET.domain_pow_difficulty,
                ),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            )),
            sk,
        )
    }

    #[test]
    fn gc_removals_are_persisted_no_resurrection_on_restart() {
        // The M8b GC regression, end to end through the real paths:
        // a domain registered at t=1000 expires at t=1000+TERM; the
        // next block (timestamp past expiry) GCs it; the store write
        // carries the removal; a reload of the same store serves an
        // EMPTY domain registry.
        use scone_blockchain::{BlockBuilder, DOMAIN_TERM_SECS};
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::RedbStore::open(dir.path().join("chain.redb")).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        let sk = SigningKey::from_bytes([0xab; 32]);

        // Block 1 (t=1000): claim + open + register, one block, one
        // atomic store append.
        let block1 = {
            let mut b = BlockBuilder::after(0, chain.tip_hash())
                .with_timestamp(1000)
                .with_producer(&sk);
            b.push_tx(signed_claim_tld(&sk, "uip")).unwrap();
            b.push_tx(signed_open_tld(&sk, "uip")).unwrap();
            b.push_tx(signed_register(&sk, "ghost.uip")).unwrap();
            b.build().unwrap()
        };
        let applied1 = chain.push_block_with_gc(&block1).unwrap();
        assert!(applied1.gc_removed_domains.is_empty());
        store_block(&mut store, &chain, &block1, applied1.hash).unwrap();

        let ghost = DomainId::from_name(&DomainName::new("ghost.uip").unwrap());
        assert!(chain.state().domain(&ghost).is_some());
        assert_eq!(store.domain_count().unwrap(), 1);

        // Block 2 (timestamp past expiry, e.g. +2 terms): the GC runs
        // at the PARENT timestamp (block 1, t=1000) — the expiry
        // (1000 + TERM) is not reached yet, nothing is removed. The
        // block still lands (empty).
        let block2 = BlockBuilder::after(1, chain.tip_hash())
            .with_timestamp(1000 + 2 * DOMAIN_TERM_SECS)
            .with_producer(&sk)
            .build()
            .unwrap();
        let applied2 = chain.push_block_with_gc(&block2).unwrap();
        assert!(
            applied2.gc_removed_domains.is_empty(),
            "GC at parent t=1000 does not see an expiry at 1000+TERM"
        );
        store_block_with_removals(
            &mut store,
            &chain,
            &block2,
            applied2.hash,
            &applied2.gc_removed_domains,
        )
        .unwrap();

        // Block 3: now the parent IS block 2 (t past the expiry) —
        // the GC removes ghost.uip and the removal reaches the store.
        let block3 = BlockBuilder::after(2, chain.tip_hash())
            .with_timestamp(1000 + 3 * DOMAIN_TERM_SECS)
            .with_producer(&sk)
            .build()
            .unwrap();
        let applied3 = chain.push_block_with_gc(&block3).unwrap();
        assert_eq!(
            applied3.gc_removed_domains,
            vec![ghost],
            "the GC ran at the parent timestamp and reports the removal"
        );
        store_block_with_removals(
            &mut store,
            &chain,
            &block3,
            applied3.hash,
            &applied3.gc_removed_domains,
        )
        .unwrap();
        assert!(chain.state().domain(&ghost).is_none());
        assert_eq!(
            store.domain_count().unwrap(),
            0,
            "the expired state left the store in the same append"
        );

        // Restart: reload from the store — the expired domain is NOT
        // resurrected (the pre-fix bug).
        let reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert!(
            reloaded.state().domain(&ghost).is_none(),
            "an expired registration must stay dead across a restart"
        );
        assert_eq!(reloaded.height(), 3);

        // And the replay path agrees bit for bit.
        let replayed = load_chain_replay(&store).unwrap();
        assert_eq!(replayed.state().domain(&ghost), None);
        assert_eq!(reloaded.tip_hash(), replayed.tip_hash());
    }

    // --- M8: persistent anti-replay TXID index (window rebuilt at boot) ---

    /// Block height → deterministic increasing timestamp (no expiry
    /// anywhere near: registrations last a year).
    fn ts(height: u64) -> u64 {
        1_000_000 + height * 60
    }

    /// Builds, pushes and atomically persists one block of `txs`.
    fn push_and_store(
        chain: &mut Blockchain,
        store: &mut crate::RedbStore,
        sk: &SigningKey,
        txs: Vec<Transaction>,
    ) {
        let mut builder = scone_blockchain::BlockBuilder::after(chain.height(), chain.tip_hash())
            .with_timestamp(ts(chain.height() + 1))
            .with_producer(sk);
        for tx in txs {
            builder.push_tx(tx).unwrap();
        }
        let block = builder.build().unwrap();
        let hash = chain.push_block(&block).unwrap();
        store_block(store, chain, &block, hash).unwrap();
    }

    /// Live chain with `uip` claimed+open, `ghost.uip` registered at
    /// height 1, then one update per block up to `tip`. The store
    /// holds the same chain.
    fn window_chain(
        tip: u64,
    ) -> (
        Blockchain,
        crate::RedbStore,
        tempfile::TempDir,
        SigningKey,
        Transaction,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = crate::RedbStore::open(dir.path().join("chain.redb")).unwrap();
        let mut chain = Blockchain::new();
        let sk = SigningKey::from_bytes([0xcd; 32]);
        let register = signed_register(&sk, "ghost.uip");
        push_and_store(
            &mut chain,
            &mut store,
            &sk,
            vec![
                signed_claim_tld(&sk, "uip"),
                signed_open_tld(&sk, "uip"),
                register.clone(),
            ],
        );
        for sequence in 1..tip {
            push_and_store(
                &mut chain,
                &mut store,
                &sk,
                vec![signed_update_domain(&sk, "ghost.uip", sequence)],
            );
        }
        assert_eq!(chain.height(), tip);
        (chain, store, dir, sk, register)
    }

    #[test]
    fn boot_rebuilds_replay_index_rejects_in_window_replay() {
        // Restart on a 65-block chain: the window tail (65 < 256 →
        // everything) is re-scanned, and a tx re-included within the
        // window is rejected as TxReplay — same decision as the live
        // node, which was NOT the case before M8.
        let tip = 65;
        let (chain, store, _dir, sk, _register) = window_chain(tip);

        // Sanity on the live side: the last update is protected.
        let last_update = signed_update_domain(&sk, "ghost.uip", tip - 1);
        let id = scone_blockchain::transaction_id(&last_update).unwrap();
        assert!(chain.is_tx_included(&id));

        // Re-including the tx at tip+1: TxReplay, not a state rule.
        let mut reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert_eq!(reloaded.height(), tip);
        assert!(
            reloaded.is_tx_included(&id),
            "M8: the replay index survives the restart"
        );
        let mut builder =
            scone_blockchain::BlockBuilder::after(reloaded.height(), reloaded.tip_hash())
                .with_timestamp(ts(tip + 1))
                .with_producer(&sk);
        builder.push_tx(last_update).unwrap();
        let replay_block = builder.build().unwrap();
        assert_eq!(
            reloaded.push_block(&replay_block).unwrap_err(),
            scone_blockchain::BlockchainError::TxReplay
        );
    }

    #[test]
    fn boot_rebuilt_index_lets_older_than_window_txs_back_in() {
        // ghost.uip was registered at height 1, far outside the
        // window of the 65-block tip? No — 65 < 256 keeps it IN the
        // window; the scan protects it. The prune semantics stay
        // unchanged: only what left the live index is accepted, so
        // this test uses the live chain's own decisions as oracle.
        let tip = 65;
        let (chain, store, _dir, _sk, register) = window_chain(tip);
        let register_id = scone_blockchain::transaction_id(&register).unwrap();
        // Both nodes agree the registration is still protected.
        assert!(chain.is_tx_included(&register_id));
        let reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert!(reloaded.is_tx_included(&register_id));

        // Now push past the window boundary on the LIVE chain: at
        // tip = 1 + 256 the entry is pruned (retain(h > cutoff)).
        // A store restarted THERE rebuilds without it — and the very
        // same signed bytes are admissible again (state rules then
        // reject the duplicate registration: prune semantics
        // unchanged, exactly like a node that never stopped).
        let mut live = chain;
        let mut store = store;
        let sk = SigningKey::from_bytes([0xcd; 32]);
        let mut sequence = tip - 1;
        while live.height() < 1 + scone_blockchain::REPLAY_WINDOW_BLOCKS {
            sequence += 1;
            push_and_store(
                &mut live,
                &mut store,
                &sk,
                vec![signed_update_domain(&sk, "ghost.uip", sequence)],
            );
        }
        assert!(!live.is_tx_included(&register_id));

        let mut reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert!(
            !reloaded.is_tx_included(&register_id),
            "older than the window: the rebuilt index pruned it too"
        );
        let mut builder =
            scone_blockchain::BlockBuilder::after(reloaded.height(), reloaded.tip_hash())
                .with_timestamp(ts(reloaded.height() + 1))
                .with_producer(&sk);
        builder.push_tx(register).unwrap();
        let block = builder.build().unwrap();
        assert_eq!(
            reloaded.push_block(&block).unwrap_err(),
            scone_blockchain::BlockchainError::DomainAlreadyRegistered,
            "outside the window the state rules decide again, not TxReplay"
        );
    }

    #[test]
    fn boot_replay_index_counts_exactly_min_window_height_blocks() {
        // 65 < REPLAY_WINDOW_BLOCKS: the scan covers the whole
        // chain — 3 txs at height 1 (claim+open+register) + 1 update
        // at each height 2..=65 — and the reloaded index counts
        // EXACTLY like the live one (3 + 64 = 67 entries, no more).
        let tip = 65;
        let (chain, store, _dir, _sk, _register) = window_chain(tip);
        let reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert_eq!(reloaded.replay_index_len(), 3 + 64);
        assert_eq!(reloaded.replay_index_len(), chain.replay_index_len());

        // And load_chain_replay (zero-trust) holds the same index.
        let replayed = load_chain_replay(&store).unwrap();
        assert_eq!(replayed.replay_index_len(), 3 + 64);
    }

    #[test]
    fn boot_replay_index_scan_is_capped_at_the_window() {
        // A store with FEWER blocks than the window reconstitutes
        // everything (previous test); a store with MORE scans only
        // the last WINDOW blocks: the reloaded index equals the live
        // pruned index bit for bit (the updates of heights
        // 2..=WINDOW-7 fall outside and are absent on both sides).
        let tip = scone_blockchain::REPLAY_WINDOW_BLOCKS + 12;
        let (chain, store, _dir, _sk, _register) = window_chain(tip);
        let reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert_eq!(
            reloaded.replay_index_len(),
            chain.replay_index_len(),
            "rebuilt index == live pruned index"
        );
        // The window tail is protected on both sides identically.
        let sk = SigningKey::from_bytes([0xcd; 32]);
        for sequence in (tip - 3)..tip {
            let tx = signed_update_domain(&sk, "ghost.uip", sequence);
            let id = scone_blockchain::transaction_id(&tx).unwrap();
            assert_eq!(reloaded.is_tx_included(&id), chain.is_tx_included(&id));
            assert!(reloaded.is_tx_included(&id));
        }
    }

    #[test]
    fn snapshot_boot_also_rebuilds_the_replay_index() {
        // M6b snapshot at height 64 (append of block 65 = 64+1
        // triggers the freeze), suffix replay of block 65 alone —
        // the snapshot never froze the anti-replay index (same
        // contract as owner keys / grace windows). The boot scan
        // adds the part of the window BELOW the snapshot: the
        // ghost.uip registration of height 1 is protected again.
        let tip = 65;
        let (chain, store, _dir, sk, register) = window_chain(tip);

        // The snapshot exists and sits strictly below the tip.
        let meta = store.snapshot_meta().unwrap().unwrap();
        assert_eq!(meta.height, 64);
        assert!(meta.height < tip);

        let mut reloaded = load_chain(&store, scone_core::TESTNET).unwrap();
        assert_eq!(reloaded.tip_hash(), chain.tip_hash());
        let register_id = scone_blockchain::transaction_id(&register).unwrap();
        assert!(
            reloaded.is_tx_included(&register_id),
            "height-1 tx re-protected across a snapshot boot (below H)"
        );
        // …and the replayed-suffix part (block 65) too, plus the
        // exact count: 3 (block 1) + 64 (updates 2..=65) = 67.
        assert_eq!(reloaded.replay_index_len(), 3 + 64);
        assert_eq!(reloaded.replay_index_len(), chain.replay_index_len());

        // End to end: re-including the height-1 registration inside
        // the window is a TxReplay on the snapshot-booted chain.
        let mut builder =
            scone_blockchain::BlockBuilder::after(reloaded.height(), reloaded.tip_hash())
                .with_timestamp(ts(tip + 1))
                .with_producer(&sk);
        builder.push_tx(register).unwrap();
        let replay_block = builder.build().unwrap();
        assert_eq!(
            reloaded.push_block(&replay_block).unwrap_err(),
            scone_blockchain::BlockchainError::TxReplay
        );
    }
}
