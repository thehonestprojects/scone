//! P0.3 + P0.4 integration tests: verified state snapshots (chunks +
//! manifest + crypto verification) and snapshot bootstrap.

use scone_core::checkpoint::{Checkpoint, CheckpointData};
use scone_core::{DomainId, DomainName, MIN_FINALITY_COMMITTEE_SIZE, Transaction, quorum_for};
use scone_crypto::SigningKey;
use scone_storage::integration::{load_chain, load_chain_replay, store_block};
use scone_storage::{
    MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES, META_VERIFIED_SNAPSHOT, NodeStore, RedbStore,
    SNAPSHOT_INTERVAL, SnapshotEntry, SnapshotPage, StorageError, VerifiedSnapshotManifest,
    export_verified_snapshot, import_verified_snapshot,
};

// ---------------------------------------------------------------- helpers

fn mined_proof(prefix: &[u8], name: &str, difficulty: u32) -> scone_core::Proof {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(prefix);
    challenge.extend_from_slice(name.as_bytes());
    let checked = scone_core::pow::mine(scone_core::TESTNET.network_id, &challenge, difficulty);
    scone_core::Proof::from_bytes(scone_core::pow::encode_proof(&checked))
}

fn sign_tx(unsigned: Transaction, sk: &SigningKey) -> Transaction {
    let payload = scone_protocol::signing_payload(&unsigned).unwrap();
    match unsigned {
        Transaction::RegisterDomain(mut r) => {
            r.signature = sk.sign(&payload);
            Transaction::RegisterDomain(r)
        }
        Transaction::RegisterTld(mut t) => {
            t.signature = sk.sign(&payload);
            Transaction::RegisterTld(t)
        }
        Transaction::SetTldOpen(mut t) => {
            t.signature = sk.sign(&payload);
            Transaction::SetTldOpen(t)
        }
        _ => unreachable!("fixtures only register/open"),
    }
}

/// One block registering one domain (`uip` claimed+opened in block 1),
/// pushed on `chain` and atomically persisted in `store`.
fn extend(
    store: &mut RedbStore,
    chain: &mut scone_blockchain::Blockchain,
    sk: &SigningKey,
    name: &str,
) -> scone_protocol::BlockHash {
    use scone_core::{RegisterDomain, RegisterTld, SetTldOpen, TldId, TldName};
    let mut builder =
        scone_blockchain::BlockBuilder::after(chain.height(), chain.tip_hash()).with_producer(sk);
    if chain.height() == 0 {
        let tld_name = TldName::new(DomainName::new(name).unwrap().tld().as_str()).unwrap();
        builder
            .push_tx(sign_tx(
                Transaction::RegisterTld(RegisterTld::register_tld_signed(
                    tld_name.clone(),
                    1,
                    mined_proof(
                        scone_core::id::TLD_ID_VERSION,
                        tld_name.as_str(),
                        scone_core::TESTNET.tld_pow_difficulty,
                    ),
                    sk.public_key(),
                    scone_crypto::Signature::from_bytes([0; 64]),
                )),
                sk,
            ))
            .unwrap();
        builder
            .push_tx(sign_tx(
                Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
                    TldId::from_tld(&tld_name),
                    true,
                    sk.public_key(),
                    scone_crypto::Signature::from_bytes([0; 64]),
                )),
                sk,
            ))
            .unwrap();
    }
    builder
        .push_tx(sign_tx(
            Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                DomainName::new(name).unwrap(),
                1,
                mined_proof(
                    scone_core::id::DOMAIN_ID_VERSION,
                    name,
                    scone_core::TESTNET.domain_pow_difficulty,
                ),
                sk.public_key(),
                scone_crypto::Signature::from_bytes([0; 64]),
            )),
            sk,
        ))
        .unwrap();
    let block = builder.build().unwrap();
    let hash = chain.push_block(&block).unwrap();
    store_block(store, chain, &block, hash).unwrap();
    hash
}

/// Source node: `SNAPSHOT_INTERVAL + 1` blocks — block 65 triggers
/// the M6b freeze of the state after block 64. Returns the store and
/// a quorum-signed checkpoint finalizing block 64 (state root
/// recomputed by replaying 1..=64, zero-trust).
fn source_node_with_finalized_checkpoint()
-> (tempfile::TempDir, RedbStore, Checkpoint, Vec<SigningKey>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.redb");
    let mut store = RedbStore::open(&path).unwrap();
    let mut chain = scone_blockchain::Blockchain::new();
    let sk = SigningKey::from_bytes([0x5a; 32]);
    for i in 1..=SNAPSHOT_INTERVAL + 1 {
        extend(&mut store, &mut chain, &sk, &format!("s{i}.uip"));
    }
    assert_eq!(chain.height(), SNAPSHOT_INTERVAL + 1);
    drop(chain);

    // Zero-trust state root at the snapshot height: replay 1..=64.
    let mut replay = scone_blockchain::Blockchain::new();
    for h in 1..=SNAPSHOT_INTERVAL {
        let bytes = store.block_at_height(h).unwrap().unwrap();
        let block: scone_protocol::Block = scone_protocol::decode_complete(&bytes).unwrap();
        replay.push_block(&block).unwrap();
    }
    let anchor_bytes = store.block_at_height(SNAPSHOT_INTERVAL).unwrap().unwrap();
    let anchor: scone_protocol::Block = scone_protocol::decode_complete(&anchor_bytes).unwrap();
    let anchor_hash = scone_blockchain::block_hash(&anchor.header).unwrap();
    let data = CheckpointData {
        epoch: 0,
        height: SNAPSHOT_INTERVAL,
        block_hash: *anchor_hash.as_bytes(),
        prev_checkpoint_hash: [0; 32],
        state_root: replay.state().state_root_smt(),
        recovery: 0,
    };
    // A quorum of the bootstrap committee signs the checkpoint — the
    // chain-layer contract `accept_checkpoint` enforces; the storage
    // import only checks snapshot ↔ checkpoint adherence.
    let keys: Vec<SigningKey> = (1..=MIN_FINALITY_COMMITTEE_SIZE as u8)
        .map(|i| SigningKey::from_bytes([i; 32]))
        .collect();
    let msg = data.signing_hash();
    let mut signatures: Vec<(scone_crypto::PublicKey, scone_crypto::Signature)> = keys
        .iter()
        .map(|sk| (sk.public_key(), sk.sign(&msg)))
        .collect();
    signatures.sort_by_key(|(pk, _)| *pk);
    let checkpoint = Checkpoint { data, signatures };
    // Sanity: the quorum really verifies.
    let committee: Vec<scone_crypto::PublicKey> = keys.iter().map(|k| k.public_key()).collect();
    assert!(checkpoint.verify_quorum(&committee, quorum_for(committee.len())));
    (dir, store, checkpoint, keys)
}

/// Exports the verified snapshot of the source node.
fn export_source(
    store: &RedbStore,
    checkpoint: &Checkpoint,
) -> (VerifiedSnapshotManifest, Vec<Vec<u8>>) {
    let (manifest, pages) = export_verified_snapshot(store, checkpoint).unwrap();
    // Structural sanity: pages decode, indices sequential, the
    // manifest hash list matches.
    assert_eq!(manifest.page_count as usize, pages.len());
    for (i, raw) in pages.iter().enumerate() {
        let page = SnapshotPage::decode(raw).unwrap();
        assert_eq!(page.index, i as u32);
        assert_eq!(page.hash(), manifest.page_hashes[i]);
    }
    (manifest, pages)
}

/// Asserts two chains are bit-identical (state, tip, SMT root).
fn assert_same_chain(a: &scone_blockchain::Blockchain, b: &scone_blockchain::Blockchain) {
    assert_eq!(a.height(), b.height());
    assert_eq!(a.tip_hash(), b.tip_hash());
    assert_eq!(a.state().state_root_smt(), b.state().state_root_smt());
    assert_eq!(a.state().len(), b.state().len());
    assert_eq!(a.state().tld_len(), b.state().tld_len());
}

// ------------------------------------------------------------------ tests

/// Export → import → boot == replay complet (état, tip,
/// state_root_smt bit-exact) ; le snapshot importé porte l'état du
/// bloc finalisé, PAS de la pointe.
#[test]
fn export_import_boot_equals_full_replay_bit_exact() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);

    // The manifest describes the finalized block 64 (not the tip 65)
    // and the exact committed root.
    assert_eq!(manifest.height, SNAPSHOT_INTERVAL);
    assert_eq!(manifest.tip_hash, checkpoint.data.block_hash);
    assert_eq!(manifest.state_root, checkpoint.data.state_root);
    assert_eq!(manifest.domain_count, SNAPSHOT_INTERVAL);
    assert_eq!(manifest.tld_count, 1);

    // Import into a fresh store, then fetch the anchor from the
    // "network" (the source store plays the network).
    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages).unwrap();

    let marker = target.verified_snapshot_marker().unwrap().unwrap();
    assert_eq!(marker.height, SNAPSHOT_INTERVAL);
    assert_eq!(marker.tip_hash, checkpoint.data.block_hash);
    assert_eq!(marker.manifest_hash, manifest.hash());
    assert_eq!(target.tip().unwrap().0, SNAPSHOT_INTERVAL);
    assert_eq!(target.domain_count().unwrap(), SNAPSHOT_INTERVAL);
    assert_eq!(target.tld_count().unwrap(), 1);

    // Before the anchor lands: typed diagnostic, not a corruption.
    let err = load_chain(&target, scone_core::TESTNET).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");

    // The relay fetches block 64 by hash and anchors it.
    let anchor_bytes = store.block_at_height(SNAPSHOT_INTERVAL).unwrap().unwrap();
    target
        .append_bootstrap_anchor(
            SNAPSHOT_INTERVAL,
            &checkpoint.data.block_hash,
            &anchor_bytes,
        )
        .unwrap();

    // Boot: full-state restore (tip == snapshot height, no suffix
    // yet) — the state is the FINALIZED state, bit-exact.
    let boot = load_chain(&target, scone_core::TESTNET).unwrap();
    assert_eq!(boot.height(), SNAPSHOT_INTERVAL);
    assert_eq!(
        boot.state().state_root_smt(),
        checkpoint.data.state_root,
        "boot state root == the root the committee signed"
    );
    // The tip block of the source node (65) is NOT in the imported
    // state: s65.uip belongs to the suffix only.
    let s65 = DomainId::from_name(&DomainName::new("s65.uip").unwrap());
    assert!(boot.state().domain(&s65).is_none());

    // The source node's full replay at the same height agrees.
    let replay = load_chain_replay(&store).unwrap();
    assert_eq!(boot.tip_hash().as_bytes(), {
        // Tip of the source chain at height 64 == the anchor.
        checkpoint.data.block_hash.as_slice()
    });
    assert_eq!(boot.state().state_root_smt(), {
        // Recompute the source state at 64 through its own snapshot
        // boot path (the M6b snapshot is the same state).
        let mut chain = scone_blockchain::Blockchain::new();
        for h in 1..=SNAPSHOT_INTERVAL {
            let bytes = store.block_at_height(h).unwrap().unwrap();
            let block: scone_protocol::Block = scone_protocol::decode_complete(&bytes).unwrap();
            chain.push_block(&block).unwrap();
        }
        chain.state().state_root_smt()
    });
    let _ = replay;
}

/// Snapshot à hauteur H puis blocs H+1..H+k rejoint (par le relay) :
/// la chaîne obtenue est identique au nœud complet (état, tip,
/// state_root_smt), et le boot rejoue SEULEMENT le suffixe.
#[test]
fn bootstrap_then_join_suffix_matches_full_node() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);
    let _ = &pages;
    let k = 3u64;

    // Extend the source (full node) to H+k first — it plays the
    // network AND the reference. Blocks 66..68 land after the export.
    {
        let mut full = load_chain_replay(&store).unwrap();
        let mut store = store.clone();
        let sk = SigningKey::from_bytes([0x5a; 32]);
        for i in (SNAPSHOT_INTERVAL + 2)..=(SNAPSHOT_INTERVAL + 1 + k) {
            extend(&mut store, &mut full, &sk, &format!("s{i}.uip"));
        }
    }
    let full = load_chain_replay(&store).unwrap();
    assert_eq!(full.height(), SNAPSHOT_INTERVAL + 1 + k);

    // Bootstrap a fresh node: import + anchor + suffix blocks
    // delivered by the relay in ascending height order.
    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages).unwrap();
    let anchor_bytes = store.block_at_height(SNAPSHOT_INTERVAL).unwrap().unwrap();
    target
        .append_bootstrap_anchor(
            SNAPSHOT_INTERVAL,
            &checkpoint.data.block_hash,
            &anchor_bytes,
        )
        .unwrap();
    let mut boot = load_chain(&target, scone_core::TESTNET).unwrap();
    for h in (SNAPSHOT_INTERVAL + 1)..=(SNAPSHOT_INTERVAL + 1 + k) {
        let bytes = store.block_at_height(h).unwrap().unwrap();
        let block: scone_protocol::Block = scone_protocol::decode_complete(&bytes).unwrap();
        let hash = boot.push_block(&block).unwrap();
        store_block(&mut target, &boot, &block, hash).unwrap();
    }

    // Boot again: the snapshot path restores H and replays ONLY the
    // suffix — the joined chain equals the full node bit for bit.
    let reloaded = load_chain(&target, scone_core::TESTNET).unwrap();
    assert_same_chain(&reloaded, &full);
    assert_eq!(reloaded.height(), SNAPSHOT_INTERVAL + 1 + k);
    // No history below H is needed: the target store never held
    // blocks 1..=63 and still reached the identical chain.
    assert!(target.block_at_height(1).unwrap().is_none());
    // The replay index covers exactly the txs at/above H (the
    // bootstrap start): a non-archive node cannot know the window
    // below H — blocks 64..=68 each carry one register tx.
    let expected_index: usize = (SNAPSHOT_INTERVAL..=SNAPSHOT_INTERVAL + 1 + k)
        .map(|h| {
            let bytes = store.block_at_height(h).unwrap().unwrap();
            let block: scone_protocol::Block = scone_protocol::decode_complete(&bytes).unwrap();
            block.transactions.len()
        })
        .sum();
    assert_eq!(
        reloaded.replay_index_len(),
        expected_index,
        "index == txs at/above the bootstrap height only"
    );
}

/// Page falsifiée (un octet) → rejet AVANT toute écriture.
#[test]
fn tampered_page_is_rejected_before_any_write() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);
    let mut pages = pages;
    // Flip one byte inside the last page's payload (not the header:
    // the page must still decode, so the HASH check is what fires).
    let last = pages.last_mut().unwrap();
    let mid = last.len() / 2;
    last[mid] ^= 0x01;

    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    let err = import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::SnapshotRejected(_) | StorageError::Corrupted(_)
        ),
        "{err}"
    );
    // Strictly nothing was written.
    assert_eq!(target.tip().unwrap().0, 0);
    assert_eq!(target.domain_count().unwrap(), 0);
    assert!(target.verified_snapshot_marker().unwrap().is_none());
}

/// Page manquante → rejet.
#[test]
fn missing_page_is_rejected() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, _pages) = export_source(&store, &checkpoint);
    // The fixture has 65 entries < 256 → a single page; drop it
    // entirely (the manifest still announces it).
    let short: Vec<Vec<u8>> = Vec::new();
    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    let err = import_verified_snapshot(&mut target, &checkpoint, &manifest, &short).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotRejected(_)), "{err}");
    assert_eq!(target.tip().unwrap().0, 0);
}

/// Mauvais state_root (manifest ↔ checkpoint incohérent, puis racine
/// recalculée ≠ racine signée) → rejet.
#[test]
fn wrong_state_root_is_rejected() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);

    // (a) checkpoint announcing a different root than the manifest.
    let mut bad_cp = checkpoint.clone();
    bad_cp.data.state_root = [0x99; 32];
    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    let err = import_verified_snapshot(&mut target, &bad_cp, &manifest, &pages).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotRejected(_)), "{err}");

    // (b) coherent manifest ↔ checkpoint but a WRONG root: the
    // entries re-folded by the importer must NOT reach it. Build a
    // forged manifest whose state_root is a lie (hashes recomputed
    // over the real pages so only the crypto check can fire).
    let mut forged_manifest = manifest.clone();
    forged_manifest.state_root = [0x99; 32];
    let mut bad_cp2 = checkpoint.clone();
    bad_cp2.data.state_root = [0x99; 32];
    let err =
        import_verified_snapshot(&mut target, &bad_cp2, &forged_manifest, &pages).unwrap_err();
    assert!(
        matches!(&err, StorageError::SnapshotRejected(m) if m.contains("state root")),
        "{err}"
    );
    // (c) a state entry swapped for another honest-looking one: the
    // page hash no longer matches the manifest.
    let mut pages2 = pages.clone();
    {
        let mut page = SnapshotPage::decode(&pages2[0]).unwrap();
        if let Some(SnapshotEntry::Domain { state, .. }) = page.entries.first_mut() {
            // Mutate one byte of the stored state, keep the encoding
            // canonical in length.
            let raw = state.0;
            let mut raw2 = raw;
            raw2[1] ^= 0x01;
            *state = scone_storage::DomainStateBytes(raw2);
        }
        pages2[0] = page.encode();
    }
    let err = import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages2).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotRejected(_)), "{err}");
    assert_eq!(target.tip().unwrap().0, 0, "nothing written");
}

/// Compteurs faux et hauteurs/tip incohérents → rejet.
#[test]
fn incoherent_counters_and_anchors_are_rejected() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);
    let fresh = || {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.redb");
        (dir, RedbStore::open(path).unwrap())
    };

    // Counter off by one.
    let mut m2 = manifest.clone();
    m2.domain_count += 1;
    let (_d, mut t) = fresh();
    assert!(import_verified_snapshot(&mut t, &checkpoint, &m2, &pages).is_err());

    // Height mismatch manifest ↔ checkpoint.
    let mut m3 = manifest.clone();
    m3.height += 1;
    let (_d, mut t) = fresh();
    let err = import_verified_snapshot(&mut t, &checkpoint, &m3, &pages).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotRejected(_)), "{err}");

    // Tip hash mismatch manifest ↔ checkpoint.
    let mut m4 = manifest.clone();
    m4.tip_hash = [0x77; 32];
    let (_d, mut t) = fresh();
    assert!(import_verified_snapshot(&mut t, &checkpoint, &m4, &pages).is_err());

    // Duplicate domain id inside a page (ordering check — the SMT
    // insert would be idempotent, so ONLY the canonical-order rule
    // catches it).
    let mut page = SnapshotPage::decode(&pages[0]).unwrap();
    if let SnapshotEntry::Domain { id, state } = page.entries[0].clone() {
        page.entries.push(SnapshotEntry::Domain { id, state });
    }
    let mut dup_pages = pages.clone();
    dup_pages[0] = page.encode();
    let mut m5 = manifest.clone();
    m5.domain_count += 1;
    m5.page_hashes[0] = SnapshotPage::decode(&dup_pages[0]).unwrap().hash();
    let (_d, mut t) = fresh();
    let err = import_verified_snapshot(&mut t, &checkpoint, &m5, &dup_pages).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotRejected(_)), "{err}");
}

/// L'import exige un store cible vide ; un second import est refusé
/// sans rien casser.
#[test]
fn import_requires_an_empty_target() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);
    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages).unwrap();
    let err = import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");
    // First import intact.
    assert_eq!(target.tip().unwrap().0, SNAPSHOT_INTERVAL);
    assert_eq!(target.domain_count().unwrap(), SNAPSHOT_INTERVAL);
}

/// L'export exige un snapshot persisté à la hauteur du checkpoint.
#[test]
fn export_requires_a_matching_persisted_snapshot() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();

    // Wrong height: a checkpoint finalizing the tip (65) has no
    // persisted snapshot to export.
    let mut cp2 = checkpoint.clone();
    cp2.data.height = SNAPSHOT_INTERVAL + 1;
    let err = export_verified_snapshot(&store, &cp2).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");

    // No snapshot at all: a young store (3 blocks, no interval
    // crossing) has nothing to export.
    let dir2 = tempfile::tempdir().unwrap();
    let mut young = RedbStore::open(dir2.path().join("young.redb")).unwrap();
    let mut chain = scone_blockchain::Blockchain::new();
    let sk = SigningKey::from_bytes([0x5a; 32]);
    for i in 1..=3 {
        extend(&mut young, &mut chain, &sk, &format!("y{i}.uip"));
    }
    let err = export_verified_snapshot(&young, &checkpoint).unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");
}

/// Le bloc d'ancrage : marqueur requis, cohérence (hauteur, hash),
/// idempotence.
#[test]
fn bootstrap_anchor_contract() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);
    let dir2 = tempfile::tempdir().unwrap();
    let mut target = RedbStore::open(dir2.path().join("target.redb")).unwrap();
    let anchor_bytes = store.block_at_height(SNAPSHOT_INTERVAL).unwrap().unwrap();

    // No marker yet.
    let err = target
        .append_bootstrap_anchor(
            SNAPSHOT_INTERVAL,
            &checkpoint.data.block_hash,
            &anchor_bytes,
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");

    import_verified_snapshot(&mut target, &checkpoint, &manifest, &pages).unwrap();

    // Wrong hash.
    let err = target
        .append_bootstrap_anchor(SNAPSHOT_INTERVAL, &[0x99; 32], &anchor_bytes)
        .unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");

    // Wrong height (marker coherence fires first — the anchor must
    // match the marker exactly).
    let err = target
        .append_bootstrap_anchor(
            SNAPSHOT_INTERVAL - 1,
            &checkpoint.data.block_hash,
            &anchor_bytes,
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::SnapshotUnavailable(_)), "{err}");

    // Correct anchor, then idempotent re-anchor.
    target
        .append_bootstrap_anchor(
            SNAPSHOT_INTERVAL,
            &checkpoint.data.block_hash,
            &anchor_bytes,
        )
        .unwrap();
    target
        .append_bootstrap_anchor(
            SNAPSHOT_INTERVAL,
            &checkpoint.data.block_hash,
            &anchor_bytes,
        )
        .unwrap();
    assert_eq!(target.tip().unwrap().0, SNAPSHOT_INTERVAL);
    assert!(target.block_at_height(SNAPSHOT_INTERVAL).unwrap().is_some());

    // After the anchor, further appends go through the ordinary
    // monotonic path (height H+1).
    let next_bytes = store
        .block_at_height(SNAPSHOT_INTERVAL + 1)
        .unwrap()
        .unwrap();
    let next: scone_protocol::Block = scone_protocol::decode_complete(&next_bytes).unwrap();
    let next_hash = scone_blockchain::block_hash(&next.header).unwrap();
    target
        .append_block_with_state(
            SNAPSHOT_INTERVAL + 1,
            next_hash.as_bytes(),
            &next_bytes,
            &scone_storage::StateDelta::empty(),
        )
        .unwrap();
    let booted = load_chain(&target, scone_core::TESTNET).unwrap();
    assert_eq!(booted.height(), SNAPSHOT_INTERVAL + 1);
}

/// Clé `meta` réservée : le marqueur ne peut pas être écrasé.
#[test]
fn verified_snapshot_marker_is_a_reserved_meta_key() {
    let (_dir, mut store, _cp, _k) = source_node_with_finalized_checkpoint();
    let err = store.meta_set(META_VERIFIED_SNAPSHOT, b"x").unwrap_err();
    assert!(matches!(err, StorageError::ReservedKey(_)), "{err}");
}

/// Roundtrip sérialisé manifest/page : le format strict rejette les
/// octets en excès et les tags inconnus.
#[test]
fn manifest_and_page_serialization_is_strict() {
    let (_dir, store, checkpoint, _keys) = source_node_with_finalized_checkpoint();
    let (manifest, pages) = export_source(&store, &checkpoint);

    // Manifest roundtrip + strictness.
    let encoded = manifest.encode();
    assert_eq!(
        VerifiedSnapshotManifest::decode(&encoded).unwrap(),
        manifest
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(VerifiedSnapshotManifest::decode(&trailing).is_err());
    let mut bad_tag = encoded.clone();
    bad_tag[0] ^= 0xff;
    assert!(VerifiedSnapshotManifest::decode(&bad_tag).is_err());

    // Page roundtrip + strictness.
    let page = SnapshotPage::decode(&pages[0]).unwrap();
    assert_eq!(SnapshotPage::decode(&page.encode()).unwrap(), page);
    let mut trailing_page = page.encode();
    trailing_page.push(0);
    assert!(SnapshotPage::decode(&trailing_page).is_err());

    // The entry budget bound is enforced (DoS guard): a page
    // announcing more entries than the bound is refused at decode.
    let mut huge = page.encode();
    let count_at = scone_storage::PAGE_TAG.len() + 4 + 8 + 32;
    let count = (scone_storage::MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES + 1) as u32;
    huge[count_at..count_at + 4].copy_from_slice(&count.to_be_bytes());
    assert!(SnapshotPage::decode(&huge).is_err());
    let _ = MAX_VERIFIED_SNAPSHOT_PAGE_ENTRIES;
}
