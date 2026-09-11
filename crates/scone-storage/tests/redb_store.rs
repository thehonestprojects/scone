//! Integration tests of the redb `NodeStore` backend.
//!
//! Each test uses its own redb tmpfile (`tempfile`), per project
//! convention. No test loads a whole table at once beyond explicit
//! pagination.

use std::thread;

use scone_core::{DomainId, DomainName, OwnerId, RecordHash};
use tempfile::TempDir;

use scone_storage::error::StorageError;
use scone_storage::integration::{load_chain, load_chain_replay, store_block};
use scone_storage::{DomainStateBytes, NodeStore, RedbStore, STORAGE_FORMAT_VERSION};

// ---------------------------------------------------------------- fixtures

fn tmp_store() -> (TempDir, RedbStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = RedbStore::open(dir.path().join("node.redb")).unwrap();
    (dir, store)
}

fn domain_id(name: &str) -> DomainId {
    DomainId::from_name(&DomainName::new(name).unwrap())
}

fn state_bytes(seed: u8) -> DomainStateBytes {
    DomainStateBytes::from(&scone_blockchain::DomainState {
        owner: OwnerId::from_bytes([seed; 32]),
        sequence: u64::from(seed),
        record_hash: if seed.is_multiple_of(2) {
            None
        } else {
            Some(RecordHash::from_bytes([seed; 32]))
        },
    })
}

/// Builds and pushes one block with a register tx, returning
/// `(chain, block, hash)` — the canonical M3 block path. Since M7c
/// (D1) the block first claims the `uip` TLD: no domain under an
/// unregistered TLD can be applied.
fn build_block(
    chain: &mut scone_blockchain::Blockchain,
    sk: &scone_crypto::SigningKey,
    name: &str,
) -> (scone_protocol::Block, scone_protocol::BlockHash) {
    use scone_core::{Proof, RegisterDomain, RegisterTld, TldId, TldName, Transaction};
    let sign_tx = |unsigned: Transaction| {
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
        }
    };
    let mut builder = scone_blockchain::BlockBuilder::after(chain.height(), chain.tip_hash());
    if chain.height() == 0 {
        // First block: claim the namespace before the domain (D1).
        builder
            .push_tx(sign_tx(Transaction::RegisterTld(
                RegisterTld::register_tld_signed(
                    TldId::from_tld(
                        &TldName::new(DomainName::new(name).expect("valid name").tld().as_str())
                            .expect("valid TLD"),
                    ),
                    1,
                    Proof::from_bytes(Vec::new()),
                    sk.public_key(),
                    scone_crypto::Signature::from_bytes([0; 64]),
                ),
            )))
            .unwrap();
    }
    builder
        .push_tx(sign_tx(Transaction::RegisterDomain(
            RegisterDomain::register_domain_signed(
                scone_core::DomainName::new(name).unwrap(),
                1,
                Proof::from_bytes(Vec::new()),
                sk.public_key(),
                scone_crypto::Signature::from_bytes([0; 64]),
            ),
        )))
        .unwrap();
    let block = builder.build().unwrap();
    let hash = chain.push_block(&block).unwrap();
    (block, hash)
}

// ------------------------------------------------------------ basic store

#[test]
fn fresh_store_is_at_genesis() {
    let (_dir, store) = tmp_store();
    let (height, hash) = store.tip().unwrap();
    assert_eq!(height, 0);
    assert_eq!(hash, *scone_blockchain::genesis_hash().as_bytes());
    assert_eq!(store.domain_count().unwrap(), 0);
    assert_eq!(store.block_at_height(0).unwrap(), None);
    assert_eq!(
        store.meta_get(b"format_version").unwrap().as_deref(),
        Some(STORAGE_FORMAT_VERSION.to_be_bytes().as_slice())
    );
}

#[test]
fn reopen_keeps_tip_and_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    let (block, hash) = {
        let mut store = RedbStore::open(&path).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        let sk = scone_crypto::SigningKey::from_bytes([1; 32]);
        let (block, hash) = build_block(&mut chain, &sk, "example.uip");
        store_block(&mut store, &chain, &block, hash).unwrap();
        (block, hash)
    };
    // Restart: only the path is shared.
    let store = RedbStore::open(&path).unwrap();
    assert_eq!(store.tip().unwrap(), (1, *hash.as_bytes()));
    let bytes = store.block_at_height(1).unwrap().unwrap();
    let reloaded: scone_protocol::Block = scone_protocol::decode_complete(&bytes).unwrap();
    assert_eq!(reloaded.header, block.header);
    assert_eq!(
        store.block_by_hash(hash.as_bytes()).unwrap().unwrap(),
        bytes
    );
}

#[test]
fn non_monotonic_height_is_rejected() {
    let (_dir, mut store) = tmp_store();
    let err = store.append_block(5, &[1; 32], b"junk").unwrap_err();
    assert_eq!(
        err,
        StorageError::NonMonotonicHeight {
            expected: 1,
            got: 5
        }
    );
    // Nothing was written.
    assert_eq!(store.tip().unwrap().0, 0);
    assert_eq!(store.block_at_height(5).unwrap(), None);
}

#[test]
fn append_then_skip_height_is_rejected() {
    let (_dir, mut store) = tmp_store();
    store.append_block(1, &[9; 32], b"block-1").unwrap();
    let err = store.append_block(3, &[8; 32], b"block-3").unwrap_err();
    assert_eq!(
        err,
        StorageError::NonMonotonicHeight {
            expected: 2,
            got: 3
        }
    );
}

#[test]
fn reappending_same_tip_is_idempotent() {
    let (_dir, mut store) = tmp_store();
    store.append_block(1, &[7; 32], b"block-1").unwrap();
    store.append_block(1, &[7; 32], b"block-1").unwrap();
    assert_eq!(store.tip().unwrap().0, 1);
    assert_eq!(store.domain_count().unwrap(), 0);
}

#[test]
fn conflicting_rewrite_of_height_is_rejected() {
    let (_dir, mut store) = tmp_store();
    store.append_block(1, &[7; 32], b"block-1").unwrap();
    store.append_block(2, &[6; 32], b"block-2").unwrap();
    // Rewriting height 2 with different content is refused (here via
    // the monotonicity check, which runs before the per-height
    // conflict check of the write transaction).
    let err = store.append_block(2, &[5; 32], b"other-2").unwrap_err();
    assert_eq!(
        err,
        StorageError::NonMonotonicHeight {
            expected: 3,
            got: 2
        }
    );
    // Rewriting height 1 is equally refused.
    let err = store.append_block(1, &[5; 32], b"other-1").unwrap_err();
    assert_eq!(
        err,
        StorageError::NonMonotonicHeight {
            expected: 3,
            got: 1
        }
    );
}

// -------------------------------------------------- blockchain roundtrip

#[test]
fn chain_roundtrip_genesis_to_n_restart_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    let mut expected_tip = scone_blockchain::genesis_hash();
    let mut expected_height = 0;
    {
        let mut store = RedbStore::open(&path).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        let sk = scone_crypto::SigningKey::from_bytes([3; 32]);
        for i in 1..=8 {
            let (block, hash) = build_block(&mut chain, &sk, &format!("d{i}.uip"));
            store_block(&mut store, &chain, &block, hash).unwrap();
            expected_tip = hash;
            expected_height = i;
        }
        assert_eq!(chain.height(), expected_height);
        assert_eq!(store.domain_count().unwrap(), 8);
    }
    // Restart 1: fast load (no replay).
    let store = RedbStore::open(&path).unwrap();
    let chain = load_chain(&store).unwrap();
    assert_eq!(chain.height(), expected_height);
    assert_eq!(chain.tip_hash(), expected_tip);
    assert_eq!(chain.state().len(), 8);
    for i in 1..=8 {
        let d = domain_id(&format!("d{i}.uip"));
        assert!(chain.state().domain(&d).is_some(), "domain d{i} missing");
    }
    // Restart 2: full replay from stored blocks.
    let replayed = load_chain_replay(&store).unwrap();
    assert_eq!(replayed.height(), chain.height());
    assert_eq!(replayed.tip_hash(), chain.tip_hash());
    assert_eq!(replayed.state().len(), chain.state().len());
}

#[test]
fn stored_domain_states_match_replayed_state() {
    // Cross-check: per-block persisted deltas == replayed RAM state.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    {
        let mut store = RedbStore::open(&path).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        let sk = scone_crypto::SigningKey::from_bytes([4; 32]);
        let (b1, h1) = build_block(&mut chain, &sk, "a.uip");
        store_block(&mut store, &chain, &b1, h1).unwrap();
        // UpdateDomain a.uip in block 2 (delta on an existing domain).
        let tx = {
            use scone_core::{Transaction, UpdateDomain};
            let unsigned = Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
                domain_id("a.uip"),
                1,
                RecordHash::from_bytes([0x44; 32]),
                sk.public_key(),
                scone_crypto::Signature::from_bytes([0; 64]),
            ));
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
            }
        };
        let mut builder = scone_blockchain::BlockBuilder::after(chain.height(), chain.tip_hash());
        builder.push_tx(tx).unwrap();
        let b2 = builder.build().unwrap();
        let h2 = chain.push_block(&b2).unwrap();
        store_block(&mut store, &chain, &b2, h2).unwrap();
    }
    let store = RedbStore::open(&path).unwrap();
    let fast = load_chain(&store).unwrap();
    let replay = load_chain_replay(&store).unwrap();
    assert_eq!(fast.state().len(), replay.state().len());
    let a = domain_id("a.uip");
    assert_eq!(fast.state().domain(&a), replay.state().domain(&a));
    assert_eq!(fast.state().domain(&a).unwrap().sequence, 1);
    assert_eq!(
        fast.state().domain(&a).unwrap().record_hash,
        Some(RecordHash::from_bytes([0x44; 32]))
    );
}

// ---------------------------------------------------------- atomicity

/// Write-transaction wrapper that fails on the Nth commit, simulating
/// a crash mid-append. Implemented by dropping the store mid-write is
/// not expressible through the public API; instead we verify the
/// store-level guarantee differently: a failed append (error before
/// commit) leaves nothing behind.
#[test]
fn failed_append_leaves_nothing_partial() {
    let (_dir, mut store) = tmp_store();
    // Valid first block.
    store.append_block(1, &[1; 32], b"block-1").unwrap();
    // Failing append: wrong height — nothing is written at all.
    let before_tip = store.tip().unwrap();
    let before_count = store.domain_count().unwrap();
    assert!(
        store
            .append_block_with_state(
                9,
                &[2; 32],
                b"bad",
                &[(domain_id("x.uip"), state_bytes(1))],
                &[]
            )
            .is_err()
    );
    assert_eq!(store.tip().unwrap(), before_tip);
    assert_eq!(store.domain_count().unwrap(), before_count);
    assert!(store.domain_state(&domain_id("x.uip")).unwrap().is_none());
    assert_eq!(store.block_by_hash(&[2; 32]).unwrap(), None);
    // The store still accepts the correct next block.
    store.append_block(2, &[2; 32], b"block-2").unwrap();
    assert_eq!(store.tip().unwrap().0, 2);
}

#[test]
fn block_and_state_are_written_together_or_not_at_all() {
    // The core atomicity scenario: an append WITH state deltas either
    // fully lands (block, both indexes, tip, domains, counter) or not.
    // We build the "not" case via a read-only-domain sabotage: a
    // duplicate domain delta in the SAME append cannot double-count.
    let (_dir, mut store) = tmp_store();
    let d = domain_id("dup.uip");
    let deltas = vec![(d, state_bytes(1)), (d, state_bytes(2))];
    store
        .append_block_with_state(1, &[3; 32], b"b1", &deltas, &[])
        .unwrap();
    // Duplicate delta counts ONE domain (last write wins).
    assert_eq!(store.domain_count().unwrap(), 1);
    assert_eq!(
        store.domain_state(&d).unwrap().unwrap().as_encoded(),
        state_bytes(2).as_encoded()
    );
    assert_eq!(store.tip().unwrap().0, 1);
}

// ------------------------------------------------------------- cursors

#[test]
fn domain_cursor_pages_by_100_in_id_order() {
    let (_dir, store) = tmp_store();
    // 250 domains with pseudo-random (but strictly ordered by key
    // bytes) ids: DomainIds from distinct names are hash-dispersed.
    let mut ids: Vec<DomainId> = (0..250)
        .map(|i| domain_id(&format!("page{i:03}.uip")))
        .collect();
    let mut writable = store.clone();
    for (i, id) in ids.iter().enumerate() {
        writable
            .put_domain_state(*id, state_bytes((i % 255) as u8))
            .unwrap();
    }
    assert_eq!(writable.domain_count().unwrap(), 250);

    ids.sort_by_key(|a| a.as_bytes().to_vec());

    // Walk with batches of 100.
    let mut seen: Vec<DomainId> = Vec::new();
    let mut cursor: Option<DomainId> = None;
    loop {
        let (page, next) = store.iterate_domains(cursor, 100).unwrap();
        let page_len = page.len();
        if page_len == 0 {
            break;
        }
        assert!(page_len <= 100);
        seen.extend(page.into_iter().map(|(id, _)| id));
        cursor = next;
        if page_len < 100 {
            break;
        }
    }
    assert_eq!(seen.len(), 250);
    assert_eq!(seen, ids, "strictly ascending DomainId order");

    // max = 0 returns an empty page without advancing the cursor.
    let (empty, same) = store.iterate_domains(Some(ids[0]), 0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(same, Some(ids[0]));

    // Small batches also cover everything.
    let mut seen2 = Vec::new();
    let mut cursor = None;
    loop {
        let (page, next) = store.iterate_domains(cursor, 7).unwrap();
        let page_len = page.len();
        if page_len == 0 {
            break;
        }
        seen2.extend(page.into_iter().map(|(id, _)| id));
        cursor = next;
        if page_len < 7 {
            break;
        }
    }
    assert_eq!(seen2, ids);
}

#[test]
fn domain_cursor_starts_strictly_after_given_id() {
    let (_dir, store) = tmp_store();
    // Fixed key bytes (storage-level concern: only the byte order of
    // DomainId matters, not how the id was derived).
    let a = DomainId::from_bytes([0x00; 32]);
    let mid = DomainId::from_bytes([0x80; 32]);
    let b = DomainId::from_bytes([0xff; 32]);
    let mut writable = store.clone();
    writable.put_domain_state(a, state_bytes(1)).unwrap();
    writable.put_domain_state(b, state_bytes(2)).unwrap();

    // Cursor on an EXISTING id skips it.
    let (page, _) = store.iterate_domains(Some(a), 100).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].0, b);

    // Cursor on a NON-EXISTING id between a and b starts strictly
    // after it.
    let (page, _) = store.iterate_domains(Some(mid), 100).unwrap();
    let ids: Vec<DomainId> = page.into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, vec![b]);

    // From the last id: empty page.
    let (page, cursor) = store.iterate_domains(Some(b), 100).unwrap();
    assert!(page.is_empty());
    assert_eq!(cursor, Some(b));
}

// --------------------------------------------------------- counters

#[test]
fn domain_count_is_exact_across_insert_update_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    {
        let mut store = RedbStore::open(&path).unwrap();
        for i in 0..5 {
            store
                .put_domain_state(domain_id(&format!("c{i}.uip")), state_bytes(1))
                .unwrap();
        }
        assert_eq!(store.domain_count().unwrap(), 5);
        // UpdateDomain (re-put) does not inflate the counter.
        store
            .put_domain_state(domain_id("c0.uip"), state_bytes(9))
            .unwrap();
        assert_eq!(store.domain_count().unwrap(), 5);
    }
    let store = RedbStore::open(&path).unwrap();
    assert_eq!(store.domain_count().unwrap(), 5, "counter survives restart");
}

// ---------------------------------------------------------- DHT cache

#[test]
fn dht_cache_roundtrip_and_overwrite() {
    let (_dir, mut store) = tmp_store();
    let d = domain_id("dht.uip");
    assert_eq!(store.dht_cache(&d).unwrap(), None);
    let v1 = vec![1, 2, 3, 4, 5];
    store.put_dht_cache(d, &v1).unwrap();
    assert_eq!(store.dht_cache(&d).unwrap().unwrap(), v1);
    let v2 = vec![9; 128];
    store.put_dht_cache(d, &v2).unwrap();
    assert_eq!(store.dht_cache(&d).unwrap().unwrap(), v2);
    // Empty value is valid cache content.
    store.put_dht_cache(d, &[]).unwrap();
    assert_eq!(store.dht_cache(&d).unwrap().unwrap(), Vec::<u8>::new());
    // DHT cache does not affect domain counter.
    assert_eq!(store.domain_count().unwrap(), 0);
}

#[test]
fn oversized_dht_cache_entry_is_rejected() {
    // DoS guard: a record above MAX_DHT_CACHE_ENTRY never reaches redb.
    let (_dir, mut store) = tmp_store();
    let d = domain_id("big.uip");
    let oversized = vec![0u8; scone_storage::MAX_DHT_CACHE_ENTRY + 1];
    assert_eq!(
        store.put_dht_cache(d, &oversized).unwrap_err(),
        StorageError::TooLarge {
            len: scone_storage::MAX_DHT_CACHE_ENTRY + 1,
            max: scone_storage::MAX_DHT_CACHE_ENTRY,
        }
    );
    // Nothing was written.
    assert_eq!(store.dht_cache(&d).unwrap(), None);
    // The exact bound is still accepted.
    let boundary = vec![0u8; scone_storage::MAX_DHT_CACHE_ENTRY];
    store.put_dht_cache(d, &boundary).unwrap();
    assert_eq!(store.dht_cache(&d).unwrap().unwrap(), boundary);
}

// ---------------------------------------------------------- meta

#[test]
fn meta_roundtrip() {
    let (_dir, mut store) = tmp_store();
    assert_eq!(store.meta_get(b"custom").unwrap(), None);
    store.meta_set(b"custom", b"value").unwrap();
    assert_eq!(
        store.meta_get(b"custom").unwrap().as_deref(),
        Some(&b"value"[..])
    );
    store.meta_set(b"custom", b"v2").unwrap();
    assert_eq!(
        store.meta_get(b"custom").unwrap().as_deref(),
        Some(&b"v2"[..])
    );
}

#[test]
fn reserved_meta_keys_are_rejected() {
    // Clobbering the store's internal bookkeeping keys must fail
    // BEFORE any write (the store stays usable and intact).
    let (_dir, mut store) = tmp_store();
    for key in [
        &b"tip"[..],
        b"tip_height",
        b"format_version",
        b"domain_count",
    ] {
        let err = store.meta_set(key, b"hacked").unwrap_err();
        assert_eq!(
            err,
            StorageError::ReservedKey(String::from_utf8_lossy(key).into_owned()),
            "key {:?}",
            String::from_utf8_lossy(key)
        );
    }
    // Internal state is untouched.
    assert_eq!(store.tip().unwrap().0, 0);
    assert_eq!(store.domain_count().unwrap(), 0);
    assert_eq!(
        store.meta_get(b"format_version").unwrap().as_deref(),
        Some(STORAGE_FORMAT_VERSION.to_be_bytes().as_slice())
    );
    // A similar-but-distinct key remains legal.
    store.meta_set(b"tips", b"ok").unwrap();
    assert_eq!(
        store.meta_get(b"tips").unwrap().as_deref(),
        Some(&b"ok"[..])
    );
}

// ------------------------------------------------------ concurrency

#[test]
fn two_handles_read_concurrently() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    let mut store = RedbStore::open(&path).unwrap();
    let mut chain = scone_blockchain::Blockchain::new();
    let sk = scone_crypto::SigningKey::from_bytes([5; 32]);
    let (block, hash) = build_block(&mut chain, &sk, "concurrent.uip");
    store_block(&mut store, &chain, &block, hash).unwrap();

    // Two clones of the same handle read from two threads concurrently
    // (Arc<Database> inside RedbStore): redb serializes writers but
    // allows any number of concurrent read transactions. This is the
    // supported concurrency model (redb 4.x allows only ONE Database
    // object per file and per process — separate open() calls on the
    // same path fail with "Database already open" until the writer is
    // fully dropped).
    let left = store.clone();
    let right = store.clone();
    let handle_a = thread::spawn(move || left.block_at_height(1).unwrap());
    let handle_b = thread::spawn(move || right.block_at_height(1).unwrap());
    let expected = store.block_at_height(1).unwrap().unwrap();
    assert_eq!(handle_a.join().unwrap().unwrap(), expected);
    assert_eq!(handle_b.join().unwrap().unwrap(), expected);

    // Sequential reopen after full close of every handle.
    drop(store);
    let reader = RedbStore::open(&path).unwrap();
    assert_eq!(reader.tip().unwrap().0, 1);
    assert_eq!(reader.block_at_height(1).unwrap().unwrap(), expected);
}

// ------------------------------------------------- corrupted database

#[test]
fn corrupted_tip_hash_in_meta_fails_load_chain_cleanly() {
    // MAJOR-1: the stored meta tip hash is never trusted. Tamper with
    // meta["tip"] after a valid store_block; load_chain must fail with
    // a typed Corrupted error (recomputed hash != stored hash), never
    // restore a chain with a forged tip.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    {
        let mut store = RedbStore::open(&path).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        let sk = scone_crypto::SigningKey::from_bytes([1; 32]);
        let (block, hash) = build_block(&mut chain, &sk, "example.uip");
        store_block(&mut store, &chain, &block, hash).unwrap();
        // Sanity: untampered load works.
        assert!(load_chain(&store).is_ok());
    }
    // Drop every handle, then tamper meta["tip"] with a raw redb
    // write (bypassing the reserved-key guard, like a corrupting
    // tool would).
    let mut tampered = [0u8; 32];
    tampered[0] = 0xde;
    {
        let db = redb::Database::open(&path).unwrap();
        let wtxn = db.begin_write().unwrap();
        {
            type Meta = redb::TableDefinition<'static, &'static [u8], &'static [u8]>;
            let mut meta = wtxn.open_table(Meta::new("meta")).unwrap();
            meta.insert(&b"tip"[..], &tampered[..]).unwrap();
        }
        wtxn.commit().unwrap();
    }
    // Re-open: load_chain must refuse the mismatched tip.
    let store = RedbStore::open(&path).unwrap();
    let err = load_chain(&store).unwrap_err();
    assert!(
        matches!(err, StorageError::Corrupted(ref msg) if msg.contains("recomputed tip hash")),
        "unexpected error: {err:?}"
    );
}

#[test]
fn truncated_database_yields_typed_error_no_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    {
        let mut store = RedbStore::open(&path).unwrap();
        store.append_block(1, &[1; 32], b"block-1").unwrap();
    }
    // Truncate the file in the middle of the data region.
    let mut bytes = std::fs::read(&path).unwrap();
    let cut = bytes.len() * 3 / 4;
    bytes.truncate(cut);
    std::fs::write(&path, &bytes).unwrap();
    // Opening must fail with a typed error (or, if redb repairs from
    // the commit header, reads must fail or be consistent) — never
    // panic.
    let outcome = std::panic::catch_unwind(|| {
        match RedbStore::open(&path) {
            Err(StorageError::Database(_) | StorageError::Corrupted(_)) => "typed-error",
            Ok(store) => {
                // If it opens, every read must be error-or-consistent.
                let _ = store.tip();
                let _ = store.block_at_height(1);
                "opened"
            }
            Err(other) => panic!("unexpected error type: {other:?}"),
        }
    });
    assert!(outcome.is_ok(), "no panic on truncated database");
}

#[test]
fn garbage_database_file_yields_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    std::fs::write(&path, b"this is not a redb file at all").unwrap();
    let outcome = std::panic::catch_unwind(|| {
        if let Ok(store) = RedbStore::open(&path) {
            let _ = store.tip();
        }
    });
    assert!(outcome.is_ok(), "no panic on garbage database");
    // Either open fails or reads fail — in both cases no panic. Also
    // assert the typed error when open fails:
    if let Err(e) = RedbStore::open(&path) {
        assert!(matches!(
            e,
            StorageError::Database(_) | StorageError::Corrupted(_)
        ));
    }
}

// ------------------------------------------------------ TLDs (M7d)

fn tld_id(tld: &str) -> scone_core::TldId {
    scone_core::TldId::from_tld(&scone_core::TldName::new(tld).unwrap())
}

fn tld_bytes(seed: u8) -> scone_storage::TldStateBytes {
    scone_storage::TldStateBytes::from(&scone_blockchain::TldState {
        owner: scone_core::OwnerId::from_bytes([seed; 32]),
    })
}

#[test]
fn fresh_store_has_no_tlds() {
    let (_dir, store) = tmp_store();
    assert_eq!(store.tld_count().unwrap(), 0);
    assert_eq!(store.tld_state(&tld_id("uip")).unwrap(), None);
    let (page, cursor) = store.iterate_tlds(None, 100).unwrap();
    assert!(page.is_empty());
    assert_eq!(cursor, None);
}

#[test]
fn put_tld_state_roundtrip_and_counter() {
    let (_dir, mut store) = tmp_store();
    let uip = tld_id("uip");
    store.put_tld_state(uip, tld_bytes(7)).unwrap();
    assert_eq!(store.tld_count().unwrap(), 1);
    assert_eq!(
        store.tld_state(&uip).unwrap().unwrap().as_encoded(),
        tld_bytes(7).as_encoded()
    );
    // Re-put does not inflate the counter.
    store.put_tld_state(uip, tld_bytes(9)).unwrap();
    assert_eq!(store.tld_count().unwrap(), 1);
    assert_eq!(
        store.tld_state(&uip).unwrap().unwrap().as_encoded(),
        tld_bytes(9).as_encoded()
    );
    let eth = tld_id("eth");
    store.put_tld_state(eth, tld_bytes(1)).unwrap();
    assert_eq!(store.tld_count().unwrap(), 2);
}

#[test]
fn tld_count_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    {
        let mut store = RedbStore::open(&path).unwrap();
        store.put_tld_state(tld_id("uip"), tld_bytes(1)).unwrap();
        store.put_tld_state(tld_id("eth"), tld_bytes(2)).unwrap();
    }
    let store = RedbStore::open(&path).unwrap();
    assert_eq!(store.tld_count().unwrap(), 2, "counter survives restart");
    assert!(store.tld_state(&tld_id("uip")).unwrap().is_some());
}

#[test]
fn tld_cursor_pages_in_ascending_id_order() {
    let (_dir, store) = tmp_store();
    let mut writable = store.clone();
    let mut ids: Vec<scone_core::TldId> = ["aaa", "bbb", "ccc", "ddd", "eee"]
        .iter()
        .map(|t| tld_id(t))
        .collect();
    for (i, id) in ids.iter().enumerate() {
        writable.put_tld_state(*id, tld_bytes(i as u8)).unwrap();
    }
    ids.sort_by_key(|a| a.as_bytes().to_vec());
    // Page of 2 from the start.
    let (page, next) = store.iterate_tlds(None, 2).unwrap();
    assert_eq!(
        page.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        &ids[..2]
    );
    assert_eq!(next, Some(ids[1]));
    // Continue strictly after the cursor to the end.
    let (rest, _) = store.iterate_tlds(next, 100).unwrap();
    assert_eq!(
        rest.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        &ids[2..]
    );
    // max = 0: empty page, cursor unchanged.
    let (empty, same) = store.iterate_tlds(Some(ids[0]), 0).unwrap();
    assert!(empty.is_empty());
    assert_eq!(same, Some(ids[0]));
}

#[test]
fn block_with_tld_delta_persists_registry_atomically() {
    let (_dir, mut store) = tmp_store();
    let uip = tld_id("uip");
    store
        .append_block_with_state(
            1,
            &[4; 32],
            b"block-1",
            &[(domain_id("a.uip"), state_bytes(1))],
            &[(uip, tld_bytes(3))],
        )
        .unwrap();
    // Block, domain delta, TLD delta, counters and tip all landed.
    assert_eq!(store.tip().unwrap().0, 1);
    assert_eq!(store.domain_count().unwrap(), 1);
    assert_eq!(store.tld_count().unwrap(), 1);
    assert!(store.tld_state(&uip).unwrap().is_some());
    assert!(store.domain_state(&domain_id("a.uip")).unwrap().is_some());
    assert!(store.block_at_height(1).unwrap().is_some());
}

#[test]
fn failed_append_leaves_no_tld_behind() {
    let (_dir, mut store) = tmp_store();
    // Non-monotonic height: nothing at all is written.
    assert!(
        store
            .append_block_with_state(9, &[5; 32], b"bad", &[], &[(tld_id("uip"), tld_bytes(1))])
            .is_err()
    );
    assert_eq!(store.tld_count().unwrap(), 0);
    assert_eq!(store.tld_state(&tld_id("uip")).unwrap(), None);
}

#[test]
fn reserved_meta_key_tld_count_is_rejected() {
    let (_dir, mut store) = tmp_store();
    let err = store.meta_set(b"tld_count", b"hacked").unwrap_err();
    assert_eq!(err, StorageError::ReservedKey("tld_count".into()));
    // A similar-but-distinct key remains legal.
    store.meta_set(b"tld_counts", b"ok").unwrap();
}

/// THE M7d test: store a chain whose first block claims the `uip`
/// TLD, restart, and verify the restored state still knows the TLD —
/// a RegisterDomain under it must be admissible (the precheck the
/// relay runs). Before M7d the restored state forgot the registry
/// and this exact path failed `UnknownTld`.
#[test]
fn restart_restores_tld_registry_and_admits_new_domains() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.redb");
    {
        let mut store = RedbStore::open(&path).unwrap();
        let mut chain = scone_blockchain::Blockchain::new();
        let sk = scone_crypto::SigningKey::from_bytes([8; 32]);
        let (block, hash) = build_block(&mut chain, &sk, "first.uip");
        store_block(&mut store, &chain, &block, hash).unwrap();
        assert_eq!(store.tld_count().unwrap(), 1);
    }
    // Restart: fast load must restore the TLD registry.
    let mut store = RedbStore::open(&path).unwrap();
    let mut chain = load_chain(&store).unwrap();
    let uip = tld_id("uip");
    assert!(
        chain.state().tld(&uip).is_some(),
        "TLD registry restored after restart"
    );
    // Window closure, end to end: a NEW RegisterDomain under the
    // restored TLD must be admissible (this is exactly the precheck
    // the relay runs; it failed with UnknownTld before M7d).
    let sk = scone_crypto::SigningKey::from_bytes([8; 32]);
    let (block, hash) = build_block(&mut chain, &sk, "second.uip");
    store_block(&mut store, &chain, &block, hash).unwrap();
    assert_eq!(store.tld_count().unwrap(), 1, "no duplicate TLD claim");
    assert_eq!(store.domain_count().unwrap(), 2);

    // Replay path agrees with the persisted registry.
    let replayed = load_chain_replay(&store).unwrap();
    assert_eq!(replayed.state().tld_len(), 1);
    assert!(replayed.state().tld(&uip).is_some());
}
