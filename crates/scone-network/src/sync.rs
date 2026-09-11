//! Block sync: bounded batch serving and boot catch-up.

use scone_protocol::limits::MAX_BLOCKS_PER_REQUEST;

/// Maximum blocks per sync response (mirrors the protocol limit; a
/// peer may ask for less).
pub const MAX_BLOCKS_PER_RESPONSE: usize = MAX_BLOCKS_PER_REQUEST;

/// Serves a bounded `GetBlocks` response from the chain + store.
///
/// Blocks at heights `start..=start+max-1` are returned in order;
/// serving stops at the current tip. Blocks no longer in RAM
/// (restored chains) are fetched one at a time from the store — never
/// all at once.
///
/// # Errors
///
/// [`crate::NetworkError`] on store/decoding failures.
pub fn serve_blocks(
    chain: &scone_blockchain::Blockchain,
    store: &impl scone_storage::NodeStore,
    start_height: u64,
    max_blocks: u32,
) -> crate::error::Result<Vec<scone_protocol::Block>> {
    let max = (max_blocks as usize).min(MAX_BLOCKS_PER_RESPONSE);
    if max == 0 {
        return Ok(Vec::new());
    }
    let tip = chain.height();
    let mut blocks = Vec::with_capacity(
        max.min(usize::try_from(tip.saturating_sub(start_height) + 1).unwrap_or(0)),
    );
    let end = start_height.saturating_add(max as u64);
    for height in start_height..end.min(tip + 1) {
        if let Some(block) = chain.block(height) {
            blocks.push(block.clone());
            continue;
        }
        // Historical block below the RAM window: served from the store.
        let Some(bytes) = store.block_at_height(height)? else {
            break;
        };
        let block =
            scone_protocol::decode_complete(&bytes).map_err(crate::NetworkError::Protocol)?;
        blocks.push(block);
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_blockchain::BlockBuilder;
    use scone_storage::RedbStore;

    fn register_domain_tx(name: &str, seed: u8) -> scone_core::Transaction {
        use scone_core::{DomainName, Proof, RegisterDomain};
        use scone_crypto::{Signature, SigningKey};
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned =
            scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                Proof::from_bytes(Vec::new()),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ));
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        match unsigned {
            scone_core::Transaction::RegisterDomain(mut r) => {
                r.signature = sk.sign(&payload);
                scone_core::Transaction::RegisterDomain(r)
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn serves_bounded_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = RedbStore::open(dir.path().join("c.redb")).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        for i in 0..5 {
            let mut builder =
                BlockBuilder::after(chain.height(), chain.tip_hash()).with_timestamp(i + 1);
            builder
                .push_tx(register_domain_tx(
                    &format!("d{i}.uip"),
                    u8::try_from(i).unwrap() + 1,
                ))
                .unwrap();
            let block = builder.build().unwrap();
            let hash = chain.push_block(&block).unwrap();
            scone_storage::integration::store_block(&mut store, &chain, &block, hash).unwrap();
        }
        // Full range.
        let blocks = serve_blocks(&chain, &store, 1, 128).unwrap();
        assert_eq!(blocks.len(), 5);
        assert_eq!(blocks[0].header.height, 1);
        // Bounded ask.
        let blocks = serve_blocks(&chain, &store, 1, 2).unwrap();
        assert_eq!(blocks.len(), 2);
        // Beyond tip.
        let blocks = serve_blocks(&chain, &store, 10, 5).unwrap();
        assert!(blocks.is_empty());
        // Zero max.
        assert!(serve_blocks(&chain, &store, 1, 0).unwrap().is_empty());
    }
}
