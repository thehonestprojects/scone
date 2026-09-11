//! Real-network integration tests: two relays on 127.0.0.1 (dynamic
//! QUIC ports), node B bootstrapped onto node A.
//!
//! Scenario (matches the M4 acceptance criteria):
//!
//! 1. A and B start at genesis; B bootstraps on A;
//! 2. a `RegisterDomain` tx is submitted to A via its control RPC;
//! 3. A produces a devnet block; B syncs it (same tip hash + height);
//! 4. the matching signed DNS record is published in the DHT at A
//!    and resolved at B (verified against the chain).
//!
//! Keypairs are test-generated; no human interaction.

use std::time::Duration;

use scone_core::{
    DnsRecord, DomainId, DomainName, OwnerId, Proof, PublicKeyRef, RecordData, RecordHash,
    RegisterDomain, Transaction, UpdateDomain,
};
use scone_crypto::{Signature, SigningKey};
use scone_network::rpc::{RpcClient, RpcRequest, RpcResponse};
use scone_network::{Config, Relay};
use scone_protocol::{encode_to_vec, signing_payload};

/// Total budget for the whole scenario (hard stop).
const TEST_BUDGET: Duration = Duration::from_secs(120);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Signs a transaction over its canonical payload (test helper).
fn sign(unsigned: Transaction, sk: &SigningKey) -> Transaction {
    let payload = signing_payload(&unsigned).expect("signing payload");
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
}

fn register_tld_tx(sk: &SigningKey, tld: &str) -> Transaction {
    sign(
        Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
            scone_core::TldName::new(tld).expect("valid tld"),
            1_700_000_000,
            mined_tld_proof(tld),
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

/// Signs a SetTldOpen tx (M8b: a fresh TLD is closed; the canonical
/// domain-registration fixture opens it).
fn set_tld_open_tx(sk: &SigningKey, tld: &str, open: bool) -> Transaction {
    sign(
        Transaction::SetTldOpen(scone_core::SetTldOpen::set_tld_open_signed(
            scone_core::TldId::from_tld(&scone_core::TldName::new(tld).expect("valid tld")),
            open,
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn register_domain_tx(sk: &SigningKey, name: &str) -> Transaction {
    sign(
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).expect("valid name"),
            1_700_000_000,
            mined_domain_proof(name),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn update_domain_tx(sk: &SigningKey, name: &str, sequence: u64, hash: [u8; 32]) -> Transaction {
    sign(
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            DomainId::from_name(&DomainName::new(name).expect("valid name")),
            sequence,
            RecordHash::from_bytes(hash),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn owner_of(sk: &SigningKey) -> OwnerId {
    OwnerId::from_public_key_ref(&PublicKeyRef::from_public_key(&sk.public_key().to_bytes()))
}

/// Builds a signed DNS record for `name` at `sequence`.
fn signed_record(sk: &SigningKey, name: &str, sequence: u64) -> scone_core::SignedDnsRecord {
    let record = DnsRecord {
        domain_id: DomainId::from_name(&DomainName::new(name).expect("valid name")),
        sequence,
        expiration: 0,
        records: vec![RecordData::A("192.0.2.1".parse().expect("ipv4"))],
    };
    let payload = encode_to_vec(&record).expect("canonical encode");
    scone_core::SignedDnsRecord {
        record,
        owner: owner_of(sk),
        signature: scone_core::Signature::from_bytes(sk.sign(&payload).to_bytes().to_vec()),
    }
}

/// Grabs a free localhost TCP port (bind + drop).
async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("free port probe");
    listener.local_addr().expect("local addr").port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_sync_blocks_and_records() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dir_b = tempfile::tempdir().expect("tempdir b");

    // ---- node A: fixed rpc port, devnet production every second ----
    let rpc_port_a = free_port().await;
    let mut config_a = Config::new(dir_a.path().to_path_buf());
    config_a.produce_interval = Duration::from_secs(1);
    config_a.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port_a));
    let mut relay_a = Relay::new(config_a).expect("relay A init");
    let peer_a = relay_a.peer_id();
    let addr_a = relay_a.wait_listen_addr().await.expect("A listen");
    tokio::spawn(async move {
        if let Err(e) = relay_a.run().await {
            eprintln!("relay A ended: {e}");
        }
    });

    // ---- node B: bootstrapped on A ---------------------------------
    let rpc_port_b = free_port().await;
    let mut config_b = Config::new(dir_b.path().to_path_buf());
    config_b.produce_interval = Duration::from_secs(1);
    config_b.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port_b));
    config_b.bootstrap = vec![format!("{addr_a}/p2p/{peer_a}")];
    let mut relay_b = Relay::new(config_b).expect("relay B init");
    let peer_b = relay_b.peer_id();
    let addr_b = relay_b.wait_listen_addr().await.expect("B listen");
    assert_ne!(peer_a, peer_b, "distinct test keypairs expected");
    tokio::spawn(async move {
        if let Err(e) = relay_b.run().await {
            eprintln!("relay B ended: {e}");
        }
    });
    let _ = addr_b;

    // Wait for both RPC surfaces.
    let client_a = wait_rpc(rpc_port_a, deadline).await;
    let client_b = wait_rpc(rpc_port_b, deadline).await;

    // Both at genesis.
    let status = status_of(&client_a, deadline).await;
    assert_eq!(status["height"], 0, "A starts at genesis: {status}");
    let status = status_of(&client_b, deadline).await;
    assert_eq!(status["height"], 0, "B starts at genesis: {status}");

    // ---- claim the TLD namespace, then the domain (D1, M7c) --------
    let sk = SigningKey::from_bytes([7u8; 32]);
    let name = "example.uip";
    let tld_hex = hex(&encode_to_vec(&register_tld_tx(&sk, "uip")).expect("encode tld tx"));
    let response = request(
        &client_a,
        RpcRequest::SubmitTx { tx_hex: tld_hex },
        deadline,
    )
    .await;
    assert!(
        response["txid"].as_str().is_some_and(|t| t.len() == 64),
        "tld txid expected: {response}"
    );
    let status_a = wait_for_height(&client_a, 1, deadline).await;
    assert_eq!(status_a["domain_count"], 0, "{status_a}");
    // M8b: open the namespace (a fresh TLD is assign-only).
    let open_hex = hex(&encode_to_vec(&set_tld_open_tx(&sk, "uip", true)).expect("encode open"));
    let response = request(
        &client_a,
        RpcRequest::SubmitTx { tx_hex: open_hex },
        deadline,
    )
    .await;
    assert!(
        response["txid"].as_str().is_some_and(|t| t.len() == 64),
        "open txid expected: {response}"
    );
    let status_a = wait_for_height(&client_a, 2, deadline).await;
    assert_eq!(status_a["domain_count"], 0, "{status_a}");
    let status_b = wait_for_same_tip(&client_b, &status_a, deadline).await;
    assert_eq!(
        status_b["height"], 2,
        "B synced the claim+open blocks: {status_b}"
    );

    // ---- submit a RegisterDomain to A -------------------------------------
    let tx_hex = hex(&encode_to_vec(&register_domain_tx(&sk, name)).expect("encode tx"));
    let response = request(
        &client_a,
        RpcRequest::SubmitTx {
            tx_hex: tx_hex.clone(),
        },
        deadline,
    )
    .await;
    assert!(
        response["txid"].as_str().is_some_and(|t| t.len() == 64),
        "txid expected: {response}"
    );

    // Wait for A to produce the block (devnet: ≤ ~2 s).
    let status_a = wait_for_height(&client_a, 3, deadline).await;
    assert_eq!(status_a["domain_count"], 1, "{status_a}");

    // ---- B syncs the block -------------------------------------------
    let status_b = wait_for_same_tip(&client_b, &status_a, deadline).await;
    assert_eq!(status_b["height"], 3, "B synced: {status_b}");
    assert_eq!(status_b["tip"], status_a["tip"], "same tip hash");

    // lookup at B: the domain registered via A is visible.
    let lookup = request(
        &client_b,
        RpcRequest::Lookup { name: name.into() },
        deadline,
    )
    .await;
    assert_eq!(lookup["registered"], true, "{lookup}");
    assert_eq!(
        lookup["owner"],
        serde_json::json!(hex(owner_of(&sk).as_bytes())),
        "{lookup}"
    );

    // ---- publish the record at A, resolve it at B ---------------------
    // First the chain must carry the record hash: an UpdateDomain tx.
    let record = signed_record(&sk, name, 1);
    let expected_hash = *scone_protocol::record_hash(&record.record).as_bytes();
    let update_hex =
        hex(&encode_to_vec(&update_domain_tx(&sk, name, 1, expected_hash)).expect("encode update"));
    let response = request(
        &client_a,
        RpcRequest::SubmitTx { tx_hex: update_hex },
        deadline,
    )
    .await;
    assert!(response["txid"].is_string(), "{response}");

    let status_a = wait_for_height(&client_a, 4, deadline).await;
    let status_b = wait_for_same_tip(&client_b, &status_a, deadline).await;
    assert_eq!(status_b["height"], 4, "B synced block 4: {status_b}");

    // Publish the signed record in the DHT via A's RPC.
    let record_hex = hex(&encode_to_vec(&record).expect("encode record"));
    let response = request(&client_a, RpcRequest::PutRecord { record_hex }, deadline).await;
    assert!(
        response["published"]
            .as_str()
            .is_some_and(|p| p.len() == 64),
        "published domain id expected: {response}"
    );

    // Resolve from B through the DHT (kad replication + verification).
    let resolved = wait_for_record(&client_b, name, deadline).await;
    assert_eq!(resolved["verified"], true, "{resolved}");
    let resolved_bytes = decode_hex(resolved["record"].as_str().expect("record hex"));
    let resolved_record: scone_core::SignedDnsRecord =
        scone_protocol::decode_complete(&resolved_bytes).expect("canonical record");
    assert_eq!(resolved_record, record, "round-tripped record");
}

/// M5 fix-up, F1 (crash prouvé) : deux `RegisterDomain` concurrents pour le
/// même nom — le second mis en mempool avant que le premier ne soit
/// miné — ne doivent JAMAIS tuer le producteur. Avant le correctif,
/// `push_block` rejetait le bloc entier (`DomainAlreadyRegistered`)
/// et `produce_if_ready` propageait l'erreur hors de `run()` : mort
/// du relay. Le relay doit rester vivant, extraire le bloc à hauteur
/// 1 (gagnant = premier tx miné) et laisser le perdant au mempool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_registers_never_kill_the_producer() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    let dir = tempfile::tempdir().expect("tempdir");
    let rpc_port = free_port().await;
    let mut config = Config::new(dir.path().to_path_buf());
    // Long interval: both transactions sit in the mempool at the same
    // production tick (precheck accepts both against the genesis
    // state), which is exactly the crash window.
    config.produce_interval = Duration::from_secs(3);
    config.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port));
    let relay = Relay::new(config).expect("relay init");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });

    let client = wait_rpc(rpc_port, deadline).await;

    // D1 (M7c): the namespace must exist before anyone races for a
    // name under it.
    let tld_sk = SigningKey::from_bytes([0x99; 32]);
    let tld_hex = hex(&encode_to_vec(&register_tld_tx(&tld_sk, "uip")).expect("encode tld"));
    let response = request(&client, RpcRequest::SubmitTx { tx_hex: tld_hex }, deadline).await;
    assert!(response["txid"].is_string(), "{response}");
    // The claim block must exist before the namespace can be opened
    // (SetTldOpen prechecks against the registry).
    let status = wait_for_height(&client, 1, deadline).await;
    assert_eq!(status["domain_count"], 0, "{status}");
    // M8b: open the namespace before the concurrent claims.
    let open_hex =
        hex(&encode_to_vec(&set_tld_open_tx(&tld_sk, "uip", true)).expect("encode open"));
    let response = request(&client, RpcRequest::SubmitTx { tx_hex: open_hex }, deadline).await;
    assert!(response["txid"].is_string(), "{response}");
    let status = wait_for_height(&client, 2, deadline).await;
    assert_eq!(status["domain_count"], 0, "{status}");

    // Two DIFFERENT owners race for the same name; both pass the
    // precheck while the domain is still free.
    let winner = SigningKey::from_bytes([0x11; 32]);
    let loser = SigningKey::from_bytes([0x22; 32]);
    let name = "race.uip";
    for sk in [&winner, &loser] {
        let tx_hex = hex(&encode_to_vec(&register_tx_sk(sk, name)).expect("encode tx"));
        let response = request(&client, RpcRequest::SubmitTx { tx_hex }, deadline).await;
        assert!(response["txid"].is_string(), "{response}");
    }

    // Height 3 gets mined with EXACTLY one of the two (the block must
    // apply cleanly); the relay stays alive and keeps answering. The
    // loser is either still pooled or already evicted by a later
    // production tick (both are non-fatal outcomes).
    let status = wait_for_height(&client, 3, deadline).await;
    assert_eq!(status["domain_count"], 1, "{status}");
    assert!(
        status["mempool"].as_u64().is_some_and(|m| m <= 1),
        "loser pooled or evicted, never fatal: {status}"
    );

    // The on-chain owner is one of the two racers, with a valid hex id.
    let lookup = request(&client, RpcRequest::Lookup { name: name.into() }, deadline).await;
    assert_eq!(lookup["registered"], true, "{lookup}");
    let owner = lookup["owner"].as_str().expect("owner hex");
    assert_eq!(owner.len(), 64);
    assert!(
        owner == hex(owner_of(&winner).as_bytes()) || owner == hex(owner_of(&loser).as_bytes()),
        "owner must be one of the racers: {lookup}"
    );

    // The relay must still work afterwards: a fresh register of a
    // DIFFERENT name goes through (height 4, still alive).
    let third = SigningKey::from_bytes([0x33; 32]);
    let tx_hex = hex(&encode_to_vec(&register_tx_sk(&third, "after.uip")).expect("encode"));
    let response = request(&client, RpcRequest::SubmitTx { tx_hex }, deadline).await;
    assert!(response["txid"].is_string(), "{response}");
    let status = wait_for_height(&client, 4, deadline).await;
    assert_eq!(status["domain_count"], 2, "{status}");
}

// ---- helpers ---------------------------------------------------------

/// Signs an arbitrary register with the given key (race test).
fn register_tx_sk(sk: &SigningKey, name: &str) -> Transaction {
    register_domain_tx(sk, name)
}

async fn request(
    client: &RpcClient,
    req: RpcRequest,
    deadline: tokio::time::Instant,
) -> serde_json::Value {
    loop {
        match client.request(req.clone()).await {
            Ok(RpcResponse::Ok { data }) => return data,
            Ok(RpcResponse::Error { message }) => {
                panic!("rpc error: {message}");
            }
            Err(e) => {
                assert!(tokio::time::Instant::now() < deadline, "rpc deadline: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn status_of(client: &RpcClient, deadline: tokio::time::Instant) -> serde_json::Value {
    request(client, RpcRequest::Status, deadline).await
}

async fn wait_rpc(port: u16, deadline: tokio::time::Instant) -> RpcClient {
    let client = RpcClient::new(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    loop {
        if let Ok(RpcResponse::Ok { .. }) = client.request(RpcRequest::Status).await {
            return client;
        }
        assert!(tokio::time::Instant::now() < deadline, "rpc never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_height(
    client: &RpcClient,
    height: u64,
    deadline: tokio::time::Instant,
) -> serde_json::Value {
    loop {
        let status = status_of(client, deadline).await;
        if status["height"].as_u64() == Some(height) {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "height {height} never reached"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_same_tip(
    client: &RpcClient,
    reference: &serde_json::Value,
    deadline: tokio::time::Instant,
) -> serde_json::Value {
    let want = reference["tip"].clone();
    loop {
        let status = status_of(client, deadline).await;
        if status["tip"] == want {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "tip {want} never reached, last: {status}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_record(
    client: &RpcClient,
    name: &str,
    deadline: tokio::time::Instant,
) -> serde_json::Value {
    loop {
        match client
            .request(RpcRequest::GetRecord { name: name.into() })
            .await
        {
            Ok(RpcResponse::Ok { data }) => return data,
            Ok(RpcResponse::Error { message }) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "record never resolvable: {message}"
                );
                // Still resolving / not found yet: retry.
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            Err(e) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "record deadline: {e}"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex digit"))
        .collect()
}
