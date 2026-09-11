//! Real-network integration tests: three relays on 127.0.0.1 (dynamic
//! QUIC ports), B and C bootstrapped onto A — a gossip CYCLE, which
//! the two-node test can never exercise.
//!
//! Security regression scenarios (audit M4):
//!
//! - **C1**: an invalid transaction (bad signature) submitted via RPC
//!   must yield an `error` response while the relay KEEPS ANSWERING
//!   the RPC (remote DoS on one message must not kill the node);
//! - **H2**: one tx submitted to A on the cycle A↔B↔C must settle
//!   everywhere with every node showing mempool size ≤ 1 and no
//!   endless re-broadcast (the gossip loop is cut by the
//!   insert-then-broadcast rule);
//! - **H1**: a `get_record` for an unregistered/unknown domain must
//!   never return `verified: true` (waiter/key binding).
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
const TEST_BUDGET: Duration = Duration::from_secs(180);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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
        Transaction::Slash(mut x) => {
            x.signature = sk.sign(&payload);
            Transaction::Slash(x)
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

/// A register tx with a FORGED signature (C1 ammo).
fn forged_register_tx(sk: &SigningKey, name: &str) -> Transaction {
    let unsigned = Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
        DomainName::new(name).expect("valid name"),
        1_700_000_000,
        Proof::from_bytes(Vec::new()),
        sk.public_key(),
        Signature::from_bytes([0xaa; 64]), // garbage signature
    ));
    // NOT signed: the signature field stays garbage.
    unsigned
}

fn owner_of(sk: &SigningKey) -> OwnerId {
    OwnerId::from_public_key_ref(&PublicKeyRef::from_public_key(&sk.public_key().to_bytes()))
}

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

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("free port probe");
    listener.local_addr().expect("local addr").port()
}

/// One relay under test, with its RPC client, peer id, listen
/// address (so later nodes can bootstrap on it) and its ADOPTED
/// anchor key (M5: the relay produces blocks with it — an allowed
/// producer — and the fixture txs are signed by the SAME key).
struct Node {
    client: RpcClient,
    peer_id: libp2p::PeerId,
    listen_addr: libp2p::Multiaddr,
    anchor: SigningKey,
}

/// Starts a relay and waits for its RPC surface. When `bootstrap` is
/// non-empty the relay dials those peers, forming the gossip topology.
/// The anchor keyfile is generated first and returned in the node:
/// `--anchor-key`-style config (M5 producer authority + checkpoint
/// signing).
async fn start_node(
    dir: &std::path::Path,
    bootstrap: &[(libp2p::Multiaddr, libp2p::PeerId)],
    anchor_env: &str,
) -> Node {
    let rpc_port = free_port().await;
    // SAFETY: env vars are written before any relay task reads them.
    unsafe { std::env::set_var(anchor_env, "three-nodes-pass") };
    let keyfile = dir.join("anchor.sconekey");
    let anchor =
        scone_keystore::create_overwriting(&keyfile, "three-nodes-pass").expect("anchor keyfile");
    let mut config = Config::new(dir.to_path_buf());
    config.produce_interval = Duration::from_secs(1);
    config.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port));
    config.anchor_key = Some(keyfile);
    config.anchor_passphrase_env = anchor_env.to_string();
    if !bootstrap.is_empty() {
        config.bootstrap = bootstrap
            .iter()
            .map(|(addr, peer)| format!("{addr}/p2p/{peer}"))
            .collect();
    }
    let mut relay = Relay::new(config).expect("relay init");
    let peer_id = relay.peer_id();
    let listen_addr = relay.wait_listen_addr().await.expect("listen");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });
    let client = RpcClient::new(std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port)));
    wait_rpc(&client, tokio::time::Instant::now() + TEST_BUDGET).await;
    Node {
        client,
        peer_id,
        listen_addr,
        anchor: anchor.signing_key,
    }
}

async fn wait_rpc(client: &RpcClient, deadline: tokio::time::Instant) {
    loop {
        if let Ok(RpcResponse::Ok { .. }) = client.request(RpcRequest::Status).await {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "rpc never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn status_of(client: &RpcClient, deadline: tokio::time::Instant) -> serde_json::Value {
    loop {
        match client.request(RpcRequest::Status).await {
            Ok(RpcResponse::Ok { data }) => return data,
            Ok(RpcResponse::Error { message }) => panic!("rpc error: {message}"),
            Err(e) => {
                assert!(tokio::time::Instant::now() < deadline, "rpc deadline: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
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
            "height {height} never reached, last: {status}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits until `pred(status)` holds, then returns that status.
async fn wait_for_status(
    client: &RpcClient,
    deadline: tokio::time::Instant,
    pred: impl Fn(&serde_json::Value) -> bool,
) -> serde_json::Value {
    loop {
        let status = status_of(client, deadline).await;
        if pred(&status) {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "status condition never met, last: {status}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits for every node to report `peers >= min`.
async fn wait_mesh_connected(nodes: &[Node], min: usize, deadline: tokio::time::Instant) {
    for node in nodes {
        wait_for_status(node.client_ref(), deadline, |s| {
            s["peers"]
                .as_u64()
                .is_some_and(|p| usize::try_from(p).is_ok_and(|p| p >= min))
        })
        .await;
    }
}

impl Node {
    fn client_ref(&self) -> &RpcClient {
        &self.client
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_cycle_security_regression() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    let dir_a = tempfile::tempdir().expect("tempdir a");
    let dir_b = tempfile::tempdir().expect("tempdir b");
    let dir_c = tempfile::tempdir().expect("tempdir c");

    // Node A first (no bootstrap), then B on A, then C on BOTH A and
    // B: the three relays form a real gossip cycle A↔B↔C. (Relying on
    // identify to relay B's address to C proved flaky.)
    let node_a = start_node(dir_a.path(), &[], "SCONE_TEST_3N_PASS_A").await;
    let (addr_a, peer_a) = (node_a.listen_addr.clone(), node_a.peer_id);
    let node_b = start_node(
        dir_b.path(),
        &[(addr_a.clone(), peer_a)],
        "SCONE_TEST_3N_PASS_B",
    )
    .await;
    let node_c = start_node(
        dir_c.path(),
        &[
            (addr_a, peer_a),
            (node_b.listen_addr.clone(), node_b.peer_id),
        ],
        "SCONE_TEST_3N_PASS_C",
    )
    .await;

    let nodes = [node_a, node_b, node_c];
    // Full mesh: every node sees the two others.
    wait_mesh_connected(&nodes, 2, deadline).await;

    // ---- C1: forged transaction must not kill the relay ----------
    // (M5: node A produces with its anchor key; every fixture tx is
    // signed by the SAME key so the producer stays allowed.)
    let sk = nodes[0].anchor.clone();
    let forged = forged_register_tx(&sk, "forged.uip");
    let forged_hex = hex(&encode_to_vec(&forged).expect("encode forged"));
    let response = nodes[0]
        .client_ref()
        .request(RpcRequest::SubmitTx { tx_hex: forged_hex })
        .await;
    match response {
        Ok(RpcResponse::Error { .. }) => {} // rejected, good
        Ok(RpcResponse::Ok { data }) => panic!("forged tx accepted: {data}"),
        Err(e) => panic!("relay died on forged tx (C1 regression): {e}"),
    }
    // The relay must STILL answer status (this is the C1 assertion).
    let status = status_of(nodes[0].client_ref(), deadline).await;
    assert_eq!(status["height"], 0, "no block from a forged tx: {status}");

    // ---- D1 (M7c): claim the namespace before the domain ----------
    let tld_hex = hex(&encode_to_vec(&register_tld_tx(&sk, "uip")).expect("encode tld"));
    let response = nodes[0]
        .client_ref()
        .request(RpcRequest::SubmitTx { tx_hex: tld_hex })
        .await;
    match response {
        Ok(RpcResponse::Ok { data }) => {
            assert!(
                data["txid"].as_str().is_some_and(|t| t.len() == 64),
                "{data}"
            );
        }
        other => panic!("tld tx rejected: {other:?}"),
    }
    for node in &nodes {
        let status = wait_for_height(node.client_ref(), 1, deadline).await;
        assert_eq!(
            status["domain_count"], 0,
            "TLD claimed, no domain yet: {status}"
        );
    }

    // M8b: open the namespace (a fresh TLD is assign-only).
    let open_hex = hex(&encode_to_vec(&set_tld_open_tx(&sk, "uip", true)).expect("encode open"));
    let response = nodes[0]
        .client_ref()
        .request(RpcRequest::SubmitTx { tx_hex: open_hex })
        .await;
    match response {
        Ok(RpcResponse::Ok { data }) => {
            assert!(
                data["txid"].as_str().is_some_and(|t| t.len() == 64),
                "{data}"
            );
        }
        other => panic!("open tx rejected: {other:?}"),
    }
    for node in &nodes {
        let status = wait_for_height(node.client_ref(), 2, deadline).await;
        assert_eq!(
            status["domain_count"], 0,
            "namespace open, no domain yet: {status}"
        );
    }

    // ---- H2: one valid tx on the cycle must settle, not loop ------
    let name = "cycle.uip";
    let tx_hex = hex(&encode_to_vec(&register_domain_tx(&sk, name)).expect("encode tx"));
    let response = nodes[0]
        .client_ref()
        .request(RpcRequest::SubmitTx {
            tx_hex: tx_hex.clone(),
        })
        .await;
    match response {
        Ok(RpcResponse::Ok { data }) => {
            assert!(
                data["txid"].as_str().is_some_and(|t| t.len() == 64),
                "{data}"
            );
        }
        other => panic!("valid tx rejected: {other:?}"),
    }

    // A produces a block; everyone syncs to height 3.
    for node in &nodes {
        let status = wait_for_height(node.client_ref(), 3, deadline).await;
        assert_eq!(
            status["domain_count"], 1,
            "domain registered everywhere: {status}"
        );
    }

    // After the cycle settles: every mempool must be EMPTY (the tx
    // landed in the block). If H2 regressed, the tx would bounce
    // forever; here we check the steady state right after the block.
    for node in &nodes {
        let status = status_of(node.client_ref(), deadline).await;
        assert_eq!(
            status["mempool"], 0,
            "no tx stuck in mempool after block: {status}"
        );
    }

    // Submit the SAME tx again to a DIFFERENT node (C): must be a
    // duplicate no-op, no re-broadcast storm.
    let response = nodes[2]
        .client_ref()
        .request(RpcRequest::SubmitTx {
            tx_hex: tx_hex.clone(),
        })
        .await;
    match response {
        // Either accepted-as-duplicate (Ok with txid) or explicit
        // state rejection (already registered) — both stop the relay
        // from relaying; what must NOT happen is an Err (dead relay)
        // or a growing mempool.
        Ok(_) => {}
        Err(e) => panic!("relay died on duplicate tx (H2 regression): {e}"),
    }
    let status = status_of(nodes[2].client_ref(), deadline).await;
    let mempool = status["mempool"].as_u64().unwrap_or(0);
    assert!(mempool <= 1, "duplicate tx must not pile up (H2): {status}");

    // ---- record publication + resolution over 3 nodes -------------
    let record = signed_record(&sk, name, 1);
    let expected_hash = *scone_protocol::record_hash(&record.record).as_bytes();
    let update_hex =
        hex(&encode_to_vec(&update_domain_tx(&sk, name, 1, expected_hash)).expect("encode update"));
    let response = nodes[1]
        .client_ref()
        .request(RpcRequest::SubmitTx { tx_hex: update_hex })
        .await;
    assert!(
        matches!(response, Ok(RpcResponse::Ok { .. })),
        "update tx accepted: {response:?}"
    );
    for node in &nodes {
        wait_for_height(node.client_ref(), 4, deadline).await;
    }

    let record_hex = hex(&encode_to_vec(&record).expect("encode record"));
    let response = nodes[0]
        .client_ref()
        .request(RpcRequest::PutRecord { record_hex })
        .await;
    match response {
        Ok(RpcResponse::Ok { data }) => {
            assert!(
                data["published"].as_str().is_some_and(|p| p.len() == 64),
                "{data}"
            );
        }
        other => panic!("put_record failed: {other:?}"),
    }

    // Resolve from C (two hops from the publisher through the DHT).
    let resolved = loop {
        match nodes[2]
            .client_ref()
            .request(RpcRequest::GetRecord { name: name.into() })
            .await
        {
            Ok(RpcResponse::Ok { data }) => break data,
            Ok(RpcResponse::Error { message }) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "record never resolvable at C: {message}"
                );
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
    };
    assert_eq!(resolved["verified"], true, "{resolved}");

    // ---- H1: an unknown domain must never resolve verified --------
    let response = nodes[1]
        .client_ref()
        .request(RpcRequest::GetRecord {
            name: "never-registered.uip".into(),
        })
        .await;
    match response {
        Ok(RpcResponse::Ok { data }) => {
            panic!("unregistered domain resolved (H1 regression): {data}");
        }
        Ok(RpcResponse::Error { .. }) => {} // correctly refused
        Err(e) => panic!("relay died on unknown-domain lookup (H1/C1): {e}"),
    }

    // Final liveness check on all three nodes.
    for node in &nodes {
        let status = status_of(node.client_ref(), deadline).await;
        assert_eq!(status["height"], 4, "everyone at height 4: {status}");
    }
}
