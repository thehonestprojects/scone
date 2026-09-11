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
        use scone_core::{DomainName, RegisterDomain};
        use scone_crypto::{Signature, SigningKey};
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned =
            scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                mined_domain_proof(name),
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

    fn register_tld_tx(tld: &str, seed: u8) -> scone_core::Transaction {
        use scone_core::{RegisterTld, TldName};
        use scone_crypto::{Signature, SigningKey};
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned = scone_core::Transaction::RegisterTld(RegisterTld::register_tld_signed(
            TldName::new(tld).unwrap(),
            1,
            mined_tld_proof(tld),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        match unsigned {
            scone_core::Transaction::RegisterTld(mut t) => {
                t.signature = sk.sign(&payload);
                scone_core::Transaction::RegisterTld(t)
            }
            _ => unreachable!(),
        }
    }

    /// Mines a testnet TLD registration proof (M8b).
    fn mined_tld_proof(tld: &str) -> scone_core::Proof {
        let mut challenge = Vec::new();
        challenge.extend_from_slice(scone_core::id::TLD_ID_VERSION);
        challenge.extend_from_slice(tld.as_bytes());
        let checked = scone_core::pow::mine(
            scone_core::TESTNET.network_id,
            &challenge,
            scone_core::TESTNET.tld_pow_difficulty,
        );
        scone_core::Proof::from_bytes(scone_core::pow::encode_proof(&checked))
    }

    /// Mines a testnet domain registration proof (M8b).
    fn mined_domain_proof(name: &str) -> scone_core::Proof {
        let mut challenge = Vec::new();
        challenge.extend_from_slice(scone_core::id::DOMAIN_ID_VERSION);
        challenge.extend_from_slice(name.as_bytes());
        let checked = scone_core::pow::mine(
            scone_core::TESTNET.network_id,
            &challenge,
            scone_core::TESTNET.domain_pow_difficulty,
        );
        scone_core::Proof::from_bytes(scone_core::pow::encode_proof(&checked))
    }

    /// Signs a SetTldOpen tx (M8b: a fresh TLD is closed; the
    /// canonical domain fixture opens it).
    fn set_tld_open_tx(seed: u8, tld: &str, open: bool) -> scone_core::Transaction {
        use scone_core::SetTldOpen;
        use scone_crypto::{Signature, SigningKey};
        let sk = SigningKey::from_bytes([seed; 32]);
        let unsigned = scone_core::Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
            scone_core::TldId::from_tld(&scone_core::TldName::new(tld).unwrap()),
            open,
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        ));
        let payload = scone_protocol::signing_payload(&unsigned).unwrap();
        match unsigned {
            scone_core::Transaction::SetTldOpen(mut t) => {
                t.signature = sk.sign(&payload);
                scone_core::Transaction::SetTldOpen(t)
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
            if i == 0 {
                // D1 (M7c) + M8b: claim the namespace, open it, then
                // the first domain (self-registration requires an
                // open TLD).
                builder.push_tx(register_tld_tx("uip", 1)).unwrap();
                builder.push_tx(set_tld_open_tx(1, "uip", true)).unwrap();
            }
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
