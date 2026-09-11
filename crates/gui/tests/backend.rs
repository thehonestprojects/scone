//! Integration tests of the GUI backend: the OwnerId explorer walks a
//! real (temp) redb store filled with signed blocks, and the hex
//! decoder is exercised on its edge cases. The RPC paths (status,
//! domain_info through the relay) are covered by the network crate's
//! own client/server roundtrip tests.

use scone_core::{
    DomainId, DomainName, OwnerId, Proof, PublicKeyRef, RegisterDomain, RegisterTld, Transaction,
};
use scone_crypto::{Signature, SigningKey};
use scone_storage::{DomainStateBytes, NodeStore, RedbStore};

use gui::backend;

/// Signs a transaction over its canonical payload.
fn sign(unsigned: Transaction, sk: &SigningKey) -> Transaction {
    let payload = scone_protocol::signing_payload(&unsigned).unwrap();
    fn ret(mut tx: Transaction, sig: scone_crypto::Signature) -> Transaction {
        match &mut tx {
            Transaction::RegisterDomain(r) => r.signature = sig,
            Transaction::RegisterTld(t) => t.signature = sig,
            Transaction::SetTldOpen(t) => t.signature = sig,
            _ => unreachable!("test helper"),
        }
        tx
    }
    let sig = sk.sign(&payload);
    ret(unsigned, sig)
}

/// Signs a `RegisterTld` for `tld` (needed since M7c: a domain can
/// only be registered under a known TLD; M8b: registration requires
/// a mined PoW and an OPEN namespace).
fn signed_register_tld(sk: &SigningKey, tld: &str) -> Transaction {
    sign(
        Transaction::RegisterTld(RegisterTld::register_tld_signed(
            scone_core::TldName::new(tld).unwrap(),
            1_700_000_000,
            mined_tld_proof(tld),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

/// Signs a `SetTldOpen` opening the namespace (M8b: a fresh TLD is
/// assign-only; `RegisterDomain` requires open).
fn signed_set_tld_open(sk: &SigningKey, tld: &str) -> Transaction {
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

/// Mines a testnet TLD registration proof (M8b).
fn mined_tld_proof(tld: &str) -> Proof {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(scone_core::id::TLD_ID_VERSION);
    challenge.extend_from_slice(tld.as_bytes());
    let checked = scone_core::pow::mine(
        scone_core::TESTNET.network_id,
        &challenge,
        scone_core::TESTNET.tld_pow_difficulty,
    );
    Proof::from_bytes(scone_core::pow::encode_proof(&checked))
}

/// Mines a testnet domain registration proof (M8b).
fn mined_domain_proof(name: &str) -> Proof {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(scone_core::id::DOMAIN_ID_VERSION);
    challenge.extend_from_slice(name.as_bytes());
    let checked = scone_core::pow::mine(
        scone_core::TESTNET.network_id,
        &challenge,
        scone_core::TESTNET.domain_pow_difficulty,
    );
    Proof::from_bytes(scone_core::pow::encode_proof(&checked))
}

/// Signs a register transaction over its canonical payload.
fn signed_register(sk: &SigningKey, name: &str) -> Transaction {
    sign(
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).unwrap(),
            1,
            mined_domain_proof(name),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

/// OwnerId of a signing key (same derivation as the CLI).
fn owner_of(sk: &SigningKey) -> OwnerId {
    let key_ref = PublicKeyRef::from_public_key(&sk.public_key().to_bytes());
    OwnerId::from_public_key_ref(&key_ref)
}

/// Builds a store at `dir/chain.redb` with one block registering the
/// given names under the key of `sk`, mirroring the relay's append
/// path: blocks_by_height + domains tables through
/// `append_block_with_state` with the chain's canonical states.
fn build_store(dir: &std::path::Path, sk: &SigningKey, names: &[&str]) {
    let mut store = RedbStore::open(dir.join("chain.redb")).unwrap();
    let mut builder = scone_blockchain::BlockBuilder::after(0, scone_blockchain::genesis_hash());
    builder.push_tx(signed_register_tld(sk, "uip")).unwrap();
    // M8b: the namespace must be OPEN for self-registration.
    builder.push_tx(signed_set_tld_open(sk, "uip")).unwrap();
    for name in names {
        builder.push_tx(signed_register(sk, name)).unwrap();
    }
    let block = builder.build().unwrap();
    // Apply through a real blockchain to get canonical blocks+states,
    // exactly like the relay's acceptance path.
    let mut chain = scone_blockchain::Blockchain::<scone_blockchain::PermissiveConsensus>::new();
    let hash = chain.push_block(&block).unwrap();
    let owner = owner_of(sk);
    let deltas: Vec<_> = names
        .iter()
        .map(|n| {
            let id = DomainId::from_name(&DomainName::new(n).unwrap());
            let state = chain.state().domain(&id).unwrap();
            (id, DomainStateBytes::from(state))
        })
        .collect();
    let _ = &owner;
    store
        .append_block_with_state(
            1,
            hash.as_bytes(),
            &scone_protocol::encode_to_vec(&block).unwrap(),
            &scone_storage::StateDelta {
                domains: deltas,
                ..scone_storage::StateDelta::empty()
            },
        )
        .unwrap();
}

#[test]
fn owner_explorer_finds_only_owned_domains() {
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::from_bytes([7; 32]);
    build_store(tmp.path(), &sk, &["a.uip", "b.uip"]);
    let owner_hex = backend::hex64(owner_of(&sk).as_bytes());

    let portfolio = backend::explore_owner(Some(tmp.path()), &owner_hex).unwrap();
    let mut names: Vec<_> = portfolio.domains.iter().map(|d| d.name.clone()).collect();
    names.sort();
    assert_eq!(names, vec!["a.uip", "b.uip"]);
    for card in &portfolio.domains {
        assert!(card.registered);
        assert_eq!(card.owner, owner_hex);
        assert_eq!(card.sequence, 0);
        assert_eq!(card.record_hash, "(none)");
        assert_eq!(card.domain_id.len(), 64);
    }
}

#[test]
fn owner_explorer_finds_nothing_for_a_foreign_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::from_bytes([7; 32]);
    build_store(tmp.path(), &sk, &["a.uip"]);
    let foreign = SigningKey::from_bytes([99; 32]);
    let portfolio = backend::explore_owner(
        Some(tmp.path()),
        &backend::hex64(owner_of(&foreign).as_bytes()),
    )
    .unwrap();
    assert!(portfolio.domains.is_empty());
}

#[test]
fn owner_explorer_reads_while_the_store_is_open_for_writing() {
    // The read-only open must coexist with a writer handle (shared
    // lock): the GUI runs alongside `scone relay`.
    let tmp = tempfile::tempdir().unwrap();
    let sk = SigningKey::from_bytes([7; 32]);
    build_store(tmp.path(), &sk, &["a.uip"]);
    let _writer_still_open = RedbStore::open(tmp.path().join("chain.redb")).unwrap();
    let portfolio =
        backend::explore_owner(Some(tmp.path()), &backend::hex64(owner_of(&sk).as_bytes()))
            .unwrap();
    assert_eq!(portfolio.domains.len(), 1);
}

#[test]
fn malformed_owner_hex_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(backend::explore_owner(Some(tmp.path()), "xyz").is_err());
    assert!(backend::explore_owner(Some(tmp.path()), &"ab".repeat(31)).is_err());
    // A missing store is a clean error, not a panic.
    assert!(backend::explore_owner(Some(tmp.path()), &"00".repeat(32)).is_err());
}
