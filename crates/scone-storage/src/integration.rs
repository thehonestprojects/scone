//! Blockchain ⟷ storage integration: persisting and replaying a chain
//! through a [`NodeStore`](crate::NodeStore).
//!
//! ## Division of responsibility
//!
//! - [`Blockchain`](scone_blockchain::Blockchain) keeps the
//!   **authoritative state in RAM** (consensus source of truth);
//! - the store is **persistence only**: block bytes + the *modified*
//!   domain states of each block (delta), never the full state.
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

use scone_blockchain::{Blockchain, DomainState, block_hash};
use scone_core::{DomainId, Transaction};
use scone_protocol::{Block, BlockHash, decode_complete, encode_to_vec};

use crate::DomainStateBytes;
use crate::NodeStore;
use crate::error::{Result, StorageError};

/// Batch size of domain-state pagination.
pub const DOMAIN_PAGE: usize = 100;

/// Domains whose state a block's transactions modify, in block order,
/// deduplicated (last write wins).
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
        // A RegisterTld never touches a domain state (separate
        // registry, M7b).
        .filter(|tx| match tx {
            Transaction::RegisterDomain(r) => seen.insert(r.domain_id),
            Transaction::UpdateDomain(u) => seen.insert(u.domain_id),
            Transaction::RegisterTld(_) => false,
        })
        .filter_map(|tx| match tx {
            Transaction::RegisterDomain(r) => Some(&r.domain_id),
            Transaction::UpdateDomain(u) => Some(&u.domain_id),
            Transaction::RegisterTld(_) => None,
        })
        .collect()
}

/// Atomic delta persistence of an accepted block.
///
/// Encodes `block` canonically, reads the final state of each touched
/// domain from the chain's RAM state (the consensus authority), and
/// writes block + tip + domain deltas in ONE store transaction.
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
    let bytes = encode_to_vec(block).map_err(|e| StorageError::Corrupted(e.to_string()))?;
    let deltas: Vec<(DomainId, DomainStateBytes)> = touched_domains(block)
        .into_iter()
        .filter_map(|id| {
            chain
                .state()
                .domain(id)
                .map(|state| (*id, DomainStateBytes::from(state)))
        })
        .collect();
    store.append_block_with_state(block.header.height, hash.as_bytes(), &bytes, &deltas)
}

/// Loads the chain from `store` **without replay**: reads the tip
/// metadata and the tip block only (O(1) block reads). The stored
/// tip hash is never trusted: it is **recomputed** from the tip
/// block header and must match (`Corrupted` otherwise). The RAM
/// state is restored from the persisted domain states, paged by
/// [`DOMAIN_PAGE`] (memory-bounded). Historical blocks stay in the
/// store and are served from there.
///
/// # Errors
///
/// [`StorageError::Corrupted`] if a stored value fails strict
/// decoding, or if the recomputed tip hash differs from the stored
/// `meta["tip"]`; [`StorageError`] on store errors.
pub fn load_chain(store: &impl NodeStore) -> Result<Blockchain> {
    let (tip_height, tip_hash) = store.tip()?;
    if tip_height == 0 {
        return Ok(Blockchain::new());
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
    Ok(Blockchain::restore(
        tip_height, recomputed, tip_block, state,
    ))
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
}
