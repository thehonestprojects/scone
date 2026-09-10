//! Real-network integration tests: two relays on 127.0.0.1 (dynamic
//! QUIC ports), node B bootstrapped onto node A.
//!
//! Scenario (matches the M4 acceptance criteria):
//!
//! 1. A and B start at genesis; B bootstraps on A;
//! 2. a `Register` tx is submitted to A via its control RPC;
//! 3. A produces a devnet block; B syncs it (same tip hash + height);
//! 4. the matching signed DNS record is published in the DHT at A
//!    and resolved at B (verified against the chain).
//!
//! Keypairs are test-generated; no human interaction.

use std::time::Duration;

use scone_core::{
    DnsRecord, DomainId, DomainName, OwnerId, Proof, PublicKeyRef, RecordData, RecordHash,
    Register, Transaction, Update,
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
        Transaction::Register(mut r) => {
            r.signature = sk.sign(&payload);
            Transaction::Register(r)
        }
        Transaction::Update(mut u) => {
            u.signature = sk.sign(&payload);
            Transaction::Update(u)
        }
    }
}

fn register_tx(sk: &SigningKey, name: &str) -> Transaction {
    sign(
        Transaction::Register(Register::register_signed(
            DomainId::from_name(&DomainName::new(name).expect("valid name")),
            1_700_000_000,
            Proof::from_bytes(Vec::new()),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn update_tx(sk: &SigningKey, name: &str, sequence: u64, hash: [u8; 32]) -> Transaction {
    sign(
        Transaction::Update(Update::update_signed(
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

    // ---- submit a Register to A -------------------------------------
    let sk = SigningKey::from_bytes([7u8; 32]);
    let name = "example.uip";
    let tx_hex = hex(&encode_to_vec(&register_tx(&sk, name)).expect("encode tx"));
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
    let status_a = wait_for_height(&client_a, 1, deadline).await;
    assert_eq!(status_a["domain_count"], 1, "{status_a}");

    // ---- B syncs the block -------------------------------------------
    let status_b = wait_for_same_tip(&client_b, &status_a, deadline).await;
    assert_eq!(status_b["height"], 1, "B synced: {status_b}");
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
    // First the chain must carry the record hash: an Update tx.
    let record = signed_record(&sk, name, 1);
    let expected_hash = *scone_protocol::record_hash(&record.record).as_bytes();
    let update_hex =
        hex(&encode_to_vec(&update_tx(&sk, name, 1, expected_hash)).expect("encode update"));
    let response = request(
        &client_a,
        RpcRequest::SubmitTx { tx_hex: update_hex },
        deadline,
    )
    .await;
    assert!(response["txid"].is_string(), "{response}");

    let status_a = wait_for_height(&client_a, 2, deadline).await;
    let status_b = wait_for_same_tip(&client_b, &status_a, deadline).await;
    assert_eq!(status_b["height"], 2, "B synced block 2: {status_b}");

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

// ---- helpers ---------------------------------------------------------

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
