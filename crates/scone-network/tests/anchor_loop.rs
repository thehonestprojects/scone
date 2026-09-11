//! Anchor-loop integration tests: checkpoint P2P wire roundtrip and
//! the full propose → sign → aggregate → gossip → finalize loop on a
//! real relay network.
//!
//! The e2e scenario needs a PoS pool ≥ 4 (MIN_FINALITY_COMMITTEE_SIZE
//! — a smaller elected committee defers finality by design, see
//! `small_committee_never_finalizes` for that guard) AND enough
//! anchors of the elected committee actually running anchor keys.
//! `scone-keystore` generates keys at creation time, so the test
//! ADOPTS the four generated keys and makes them the whole PoS pool
//! (four domains, one per anchor key): with pool size == committee
//! size (4), the elected committee is the whole pool whatever the
//! draw — every relay is an anchor of the committee.

use std::time::Duration;

use scone_core::checkpoint::{Checkpoint, CheckpointData};
use scone_core::{
    DomainId, DomainName, Proof, RecordHash, RegisterDomain, Transaction, UpdateDomain,
};
use scone_crypto::SigningKey;
use scone_network::rpc::{RpcClient, RpcRequest, RpcResponse};
use scone_network::{Config, Relay};
use scone_protocol::{Message, decode_complete, encode_to_vec, signing_payload};

/// Total budget of the e2e scenario (generous: real QUIC relays).
const TEST_BUDGET: Duration = Duration::from_secs(60);

// ------------------------------------------------------------------
// Wire roundtrip through a relayed Message envelope
// ------------------------------------------------------------------

fn cp_fixture() -> Checkpoint {
    let sk = SigningKey::from_bytes([7; 32]);
    let data = CheckpointData {
        epoch: 3,
        height: 33,
        block_hash: [1; 32],
        prev_checkpoint_hash: [2; 32],
        state_root: [3; 32],
        recovery: 0,
    };
    let msg = data.signing_hash();
    Checkpoint {
        data,
        signatures: vec![(sk.public_key(), sk.sign(&msg))],
    }
}

#[test]
fn checkpoint_message_wire_roundtrip() {
    let cp = cp_fixture();
    let message = Message::Checkpoint(Box::new(cp.clone()));
    let bytes = encode_to_vec(&message).expect("encode");
    let decoded: Message = decode_complete(&bytes).expect("decode");
    assert_eq!(decoded, message);
    // The carried checkpoint still verifies against its signer.
    match decoded {
        Message::Checkpoint(inner) => {
            assert!(inner.verify_quorum(&[cp.signatures[0].0], 1));
        }
        _ => panic!("wrong variant decoded"),
    }
    // GetCheckpoints is a bare discriminant.
    assert_eq!(
        encode_to_vec(&Message::GetCheckpoints).unwrap(),
        vec![scone_protocol::message::msg_type::GET_CHECKPOINTS]
    );
}

// ------------------------------------------------------------------
// e2e: 4 anchor relays finalize a checkpoint
// ------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mines a testnet TLD registration proof.
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

/// Mines a testnet domain registration proof.
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

fn sign_tx(unsigned: Transaction, sk: &SigningKey) -> Transaction {
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
        Transaction::SetTldOpen(mut s) => {
            s.signature = sk.sign(&payload);
            Transaction::SetTldOpen(s)
        }
        _ => unreachable!("fixtures use only these tx types"),
    }
}

fn register_tld_tx(sk: &SigningKey, tld: &str) -> Transaction {
    sign_tx(
        Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
            scone_core::TldName::new(tld).expect("valid tld"),
            1_700_000_000,
            mined_tld_proof(tld),
            sk.public_key(),
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn set_tld_open_tx(sk: &SigningKey, tld: &str) -> Transaction {
    sign_tx(
        Transaction::SetTldOpen(scone_core::SetTldOpen::set_tld_open_signed(
            scone_core::TldId::from_tld(&scone_core::TldName::new(tld).expect("valid tld")),
            true,
            sk.public_key(),
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn register_domain_tx(sk: &SigningKey, name: &str) -> Transaction {
    sign_tx(
        Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            DomainName::new(name).expect("valid name"),
            1_700_000_000,
            mined_domain_proof(name),
            sk.public_key(),
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

#[allow(dead_code)]
fn update_domain_tx(sk: &SigningKey, name: &str, sequence: u64) -> Transaction {
    sign_tx(
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            DomainId::from_name(&DomainName::new(name).expect("valid name")),
            sequence,
            RecordHash::from_bytes([9; 32]),
            sk.public_key(),
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("free port probe");
    listener.local_addr().expect("local addr").port()
}

struct Node {
    client: RpcClient,
    peer_id: libp2p::PeerId,
    listen_addr: libp2p::Multiaddr,
}

/// Prepares one anchor dir: keyfile (key ADOPTED afterwards) + env
/// var, then spawns the relay on the given bootstrap topology.
async fn spawn_anchor(
    dir: &std::path::Path,
    env: &str,
    passphrase: &str,
    bootstrap: &[(libp2p::Multiaddr, libp2p::PeerId)],
) -> (Node, SigningKey) {
    let keyfile = dir.join("anchor.sconekey");
    let generated = scone_keystore::create_overwriting(&keyfile, passphrase).expect("keyfile");

    let rpc_port = free_port().await;
    let mut config = Config::new(dir.to_path_buf());
    config.produce_interval = Duration::from_secs(1);
    config.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port));
    config.anchor_key = Some(keyfile);
    config.anchor_passphrase_env = env.to_string();
    if !bootstrap.is_empty() {
        config.bootstrap = bootstrap
            .iter()
            .map(|(addr, peer)| format!("{addr}/p2p/{peer}"))
            .collect();
    }
    let mut relay = Relay::new(config).expect("relay init");
    let peer_id = relay.peer_id();
    let listen_addr = relay.wait_listen_addr().await.expect("listen");
    let rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port));
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });
    let client = RpcClient::new(rpc_addr);
    wait_rpc(&client, tokio::time::Instant::now() + TEST_BUDGET).await;
    (
        Node {
            client,
            peer_id,
            listen_addr,
        },
        generated.signing_key,
    )
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

/// Waits until the relay reports `height >= min`.
async fn wait_height(client: &RpcClient, min: u64, deadline: tokio::time::Instant) {
    loop {
        let status = status_of(client, deadline).await;
        if status["height"].as_u64().is_some_and(|h| h >= min) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "height {min} never reached, last: {status}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Submits a tx hex, asserting acceptance.
async fn submit(client: &RpcClient, tx: &Transaction) {
    let bytes = encode_to_vec(tx).expect("tx encode");
    match client
        .request(RpcRequest::SubmitTx {
            tx_hex: hex(&bytes),
        })
        .await
    {
        Ok(RpcResponse::Ok { .. }) => {}
        other => panic!("submit_tx rejected: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_anchors_finalize_and_propagate_a_checkpoint() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    // Four temp dirs; each keyfile's ADOPTED key becomes one pool seat.
    let dirs: Vec<_> = (0..4)
        .map(|_| tempfile::tempdir().expect("tempdir"))
        .collect();
    let passphrases: Vec<String> = (0..4).map(|i| format!("anchor-pass-{i}")).collect();
    let envs: Vec<String> = (0..4)
        .map(|i| format!("SCONE_TEST_ANCHOR_PASS_{i}"))
        .collect();
    // Env setup happens once, before any task that reads the vars.
    // SAFETY: single-threaded section of the test (no threads spawned yet).
    unsafe {
        for (env, pass) in envs.iter().zip(&passphrases) {
            std::env::set_var(env, pass);
        }
    }

    // A first, then B on A, C on A+B, D on A+B+C (full gossip mesh,
    // mirroring three_nodes.rs).
    let (node_a, key_a) = spawn_anchor(dirs[0].path(), &envs[0], &passphrases[0], &[]).await;
    let (addr_a, peer_a) = (node_a.listen_addr.clone(), node_a.peer_id);
    let (node_b, key_b) = spawn_anchor(
        dirs[1].path(),
        &envs[1],
        &passphrases[1],
        &[(addr_a.clone(), peer_a)],
    )
    .await;
    let (node_c, key_c) = spawn_anchor(
        dirs[2].path(),
        &envs[2],
        &passphrases[2],
        &[
            (addr_a.clone(), peer_a),
            (node_b.listen_addr.clone(), node_b.peer_id),
        ],
    )
    .await;
    let (node_d, key_d) = spawn_anchor(
        dirs[3].path(),
        &envs[3],
        &passphrases[3],
        &[
            (addr_a, peer_a),
            (node_b.listen_addr.clone(), node_b.peer_id),
            (node_c.listen_addr.clone(), node_c.peer_id),
        ],
    )
    .await;
    let nodes = [&node_a, &node_b, &node_c, &node_d];
    let adopted = [&key_a, &key_b, &key_c, &key_d];

    // Bootstrap the pool: the FIRST anchor claims + opens the TLD and
    // registers one domain per anchor key (four seats). State-dependent
    // prechecks run against the APPLIED state, so each stage waits for
    // its block before the next submission.
    submit(&node_a.client, &register_tld_tx(&key_a, "uip")).await;
    wait_height(&node_a.client, 1, deadline).await;
    submit(&node_a.client, &set_tld_open_tx(&key_a, "uip")).await;
    wait_height(&node_a.client, 2, deadline).await;
    for (i, key) in adopted.iter().enumerate() {
        submit(
            &node_a.client,
            &register_domain_tx(key, &format!("anchor{i}.uip")),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // epoch_min_blocks = 4: finality opens once height ≥ 5. The four
    // pool seats are in (domain_count = 4); the anchor loop takes it
    // from here — no extra block feeding needed.

    // Every node finalizes a checkpoint within the budget.
    for (i, node) in nodes.iter().enumerate() {
        loop {
            let status = status_of(&node.client, deadline).await;
            if status["checkpoints"].as_u64().is_some_and(|c| c >= 1) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "node {i} never finalized a checkpoint, last status: {status}"
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    // All four finalized the SAME epoch (consensus on finality).
    let mut epochs = Vec::new();
    for node in &nodes {
        let status = status_of(&node.client, deadline).await;
        epochs.push(status["finalized_epoch"].as_u64().expect("epoch set"));
    }
    assert!(epochs.iter().all(|e| *e == epochs[0]), "epochs: {epochs:?}");
}

// ----------------------------------------------------------------------
// Guard: a committee below the BFT floor never finalizes
// ----------------------------------------------------------------------

/// Unit-level guard (no network): a chain whose elected committee is
/// of size 1 (< MIN_FINALITY_COMMITTEE_SIZE) refuses a checkpoint even
/// signed by that sole member — finality is deferred, never claimed
/// below the BFT floor.
#[test]
fn small_committee_never_finalizes() {
    use scone_blockchain::Blockchain;

    let mut chain = Blockchain::new(); // testnet: committee_size = 4
    let sk = SigningKey::from_bytes([1; 32]);
    // Pool of one: claim TLD + domain owned by `sk` (block-level, no
    // relay needed). Blocks are signed by `sk` (allowed producer:
    // bootstrap pool owner). testnet epoch_min_blocks = 4: build four
    // blocks so a proposal becomes possible, then check the guard.
    let mut timestamp = 1u64;
    for round in 0..4u64 {
        let mut builder = scone_blockchain::BlockBuilder::after(chain.height(), chain.tip_hash())
            .with_timestamp(timestamp)
            .with_producer(&sk);
        if round == 0 {
            builder.push_tx(register_tld_tx(&sk, "uip")).unwrap();
            builder.push_tx(set_tld_open_tx(&sk, "uip")).unwrap();
            builder
                .push_tx(register_domain_tx(&sk, "solo.uip"))
                .unwrap();
        }
        let block = builder.build().unwrap();
        chain.push_block(&block).expect("bootstrap block applies");
        timestamp += 1;
    }
    let _ = timestamp;

    // Committee of the bootstrap pool: 1 elected member (pool of 1).
    let data = chain.propose_checkpoint().expect("proposal possible");
    let msg = data.signing_hash();
    let cp = Checkpoint {
        data,
        signatures: vec![(sk.public_key(), sk.sign(&msg))],
    };
    let err = chain
        .accept_checkpoint(cp)
        .expect_err("below the BFT floor finality must be refused");
    let text = err.to_string();
    assert!(
        text.to_lowercase().contains("floor"),
        "unexpected error: {text}"
    );
}
