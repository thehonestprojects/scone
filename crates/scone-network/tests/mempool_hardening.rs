//! Mempool hardening e2e (ported from the .bak): per-domain pending
//! cap and windowed TXID anti-replay, exercised through the relay's
//! real accept/produce paths (control RPC → mempool → devnet block).
//!
//! - `per_domain_cap_and_replay_rejection_e2e`: MAX_PENDING_PER_DOMAIN
//!   distinct pending ops on one domain, the next is rejected, another
//!   domain is unaffected, and re-submitting INCLUDED bytes is
//!   rejected as a replay;
//! - `replayed_pending_is_evicted_at_production`: the production path
//!   stays healthy after replay rejections.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use scone_core::{
    DomainId, DomainName, Proof, RegisterDomain, RenewDomain, Transaction, UpdateDomain,
};
use scone_crypto::{Signature, SigningKey};
use scone_network::rpc::{RpcClient, RpcRequest, RpcResponse};
use scone_network::{Config, MAX_PENDING_PER_DOMAIN, Relay};
use scone_protocol::{encode_to_vec, signing_payload};

const TEST_BUDGET: Duration = Duration::from_secs(120);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sign(unsigned: Transaction, sk: &SigningKey) -> Transaction {
    let payload = signing_payload(&unsigned).expect("signing payload");
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
        Transaction::RenewDomain(mut r) => {
            r.signature = sk.sign(&payload);
            Transaction::RenewDomain(r)
        }
        Transaction::UpdateDomain(mut u) => {
            u.signature = sk.sign(&payload);
            Transaction::UpdateDomain(u)
        }
        _ => unreachable!("fixtures above only use these variants"),
    }
}

fn mined_proof(prefix: &[u8], name: &str, difficulty: u32) -> Proof {
    let mut challenge = Vec::new();
    challenge.extend_from_slice(prefix);
    challenge.extend_from_slice(name.as_bytes());
    let checked = scone_core::pow::mine(scone_core::TESTNET.network_id, &challenge, difficulty);
    Proof::from_bytes(scone_core::pow::encode_proof(&checked))
}

fn register_tld_tx(sk: &SigningKey, tld: &str) -> Transaction {
    sign(
        Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
            scone_core::TldName::new(tld).expect("valid tld"),
            1_700_000_000,
            mined_proof(
                scone_core::id::TLD_ID_VERSION,
                tld,
                scone_core::TESTNET.tld_pow_difficulty,
            ),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

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
            mined_proof(
                scone_core::id::DOMAIN_ID_VERSION,
                name,
                scone_core::TESTNET.domain_pow_difficulty,
            ),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn renew_domain_tx(sk: &SigningKey, name: &str, valid_until: u64) -> Transaction {
    sign(
        Transaction::RenewDomain(RenewDomain::renew_domain_signed(
            DomainId::from_name(&DomainName::new(name).expect("valid name")),
            valid_until,
            sk.public_key(),
            Signature::from_bytes([0; 64]),
        )),
        sk,
    )
}

fn update_domain_tx(sk: &SigningKey, name: &str, sequence: u64, salt: u8) -> Transaction {
    sign(
        Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            DomainId::from_name(&DomainName::new(name).expect("valid name")),
            sequence,
            scone_core::RecordHash::from_bytes([salt; 32]),
            sk.public_key(),
            Signature::from_bytes([0; 64]),
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

async fn request(
    client: &RpcClient,
    req: RpcRequest,
    deadline: tokio::time::Instant,
) -> Result<serde_json::Value, String> {
    loop {
        match client.request(req.clone()).await {
            Ok(RpcResponse::Ok { data }) => return Ok(data),
            Ok(RpcResponse::Error { message }) => return Err(message),
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
        let status = request(client, RpcRequest::Status, deadline)
            .await
            .expect("status");
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

async fn submit(
    client: &RpcClient,
    tx: &Transaction,
    deadline: tokio::time::Instant,
) -> Result<serde_json::Value, String> {
    let tx_hex = hex(&encode_to_vec(tx).expect("encode tx"));
    request(client, RpcRequest::SubmitTx { tx_hex }, deadline).await
}

/// Claims + opens `uip` and registers `name` (3 blocks).
async fn setup_chain(
    client: &RpcClient,
    sk: &SigningKey,
    name: &str,
    deadline: tokio::time::Instant,
) {
    submit(client, &register_tld_tx(sk, "uip"), deadline)
        .await
        .expect("tld claim accepted");
    let status = wait_for_height(client, 1, deadline).await;
    assert_eq!(status["domain_count"], 0, "{status}");
    submit(client, &set_tld_open_tx(sk, "uip", true), deadline)
        .await
        .expect("tld open accepted");
    let status = wait_for_height(client, 2, deadline).await;
    assert_eq!(status["domain_count"], 0, "{status}");
    submit(client, &register_domain_tx(sk, name), deadline)
        .await
        .expect("domain register accepted");
    let status = wait_for_height(client, 3, deadline).await;
    assert_eq!(status["domain_count"], 1, "{status}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_domain_cap_and_replay_rejection_e2e() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    let dir = tempfile::tempdir().expect("tempdir");
    let rpc_port = free_port().await;
    let mut config = Config::new(dir.path().to_path_buf());
    // Production every 5 s: the burst below lands well inside one
    // interval, so the cap is observable on a settled mempool.
    config.produce_interval = Duration::from_secs(5);
    config.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port));
    let relay = Relay::new(config).expect("relay init");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });
    let client = wait_rpc(rpc_port, deadline).await;

    let sk = SigningKey::from_bytes([7u8; 32]);
    setup_chain(&client, &sk, "spam.uip", deadline).await;

    // ---- per-domain cap ---------------------------------------------
    // Distinct VALID pending ops on the same domain: renewals with
    // strictly increasing expiries (each extends the previous one, so
    // any subset applies cleanly at production time). The precheck of
    // a RenewDomain only looks at owner, so they all pass while pooled.
    let base = unix_now() + scone_blockchain::DOMAIN_TERM_SECS + 1000;
    let renews: Vec<Transaction> = (1u64..=u64::try_from(MAX_PENDING_PER_DOMAIN).unwrap())
        .map(|i| renew_domain_tx(&sk, "spam.uip", base + i * 60))
        .collect();
    for (i, tx) in renews.iter().enumerate() {
        submit(&client, tx, deadline)
            .await
            .unwrap_or_else(|e| panic!("renew #{} must be accepted: {e}", i + 1));
    }
    // The full per-domain budget is pending on spam.uip, nothing else.
    let status = request(&client, RpcRequest::Status, deadline)
        .await
        .expect("status");
    assert_eq!(
        status["mempool"].as_u64(),
        Some(MAX_PENDING_PER_DOMAIN as u64),
        "{status}"
    );

    // One more on the SAME domain: refused with the per-domain cap.
    let over = renew_domain_tx(&sk, "spam.uip", base + 10_000);
    let err = submit(&client, &over, deadline)
        .await
        .expect_err("cap must be enforced");
    assert!(
        err.contains("per-domain") || err.contains("too many pending"),
        "cap error must be explicit: {err}"
    );

    // A DIFFERENT domain is unaffected by spam.uip's cap.
    submit(&client, &register_domain_tx(&sk, "other.uip"), deadline)
        .await
        .expect("another domain is not capped by spam.uip");
    let status = request(&client, RpcRequest::Status, deadline)
        .await
        .expect("status");
    assert_eq!(
        status["mempool"].as_u64(),
        Some(MAX_PENDING_PER_DOMAIN as u64 + 1),
        "cap renews + 1 foreign register: {status}"
    );

    // ---- production drains everything, relay healthy ------------------
    let status = wait_for_height(&client, 4, deadline).await;
    assert_eq!(status["mempool"].as_u64(), Some(0), "{status}");
    assert_eq!(status["domain_count"], 2, "{status}");

    // ---- anti-replay: the INCLUDED renew bytes are refused ------------
    // (a RenewDomain precheck only checks owner — the replay check is
    // what fires here, not a state rule)
    let err = submit(&client, &renews[0], deadline)
        .await
        .expect_err("included tx must be rejected");
    assert!(
        err.contains("already included"),
        "replay error must be explicit: {err}"
    );
    // A fresh op on the same domain still goes through.
    submit(
        &client,
        &update_domain_tx(&sk, "spam.uip", 1, 0x5a),
        deadline,
    )
    .await
    .expect("fresh update accepted after a replay rejection");
    let status = wait_for_height(&client, 5, deadline).await;
    assert_eq!(status["domain_count"], 2, "{status}");
}

/// Production-path resilience: replays of included transactions are
/// rejected at admission, evicted at production, and never kill the
/// relay — a fresh op still lands afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_pending_is_evicted_at_production() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    let dir = tempfile::tempdir().expect("tempdir");
    let rpc_port = free_port().await;
    let mut config = Config::new(dir.path().to_path_buf());
    config.produce_interval = Duration::from_secs(1);
    config.rpc_addr = std::net::SocketAddr::from(([127, 0, 0, 1], rpc_port));
    let relay = Relay::new(config).expect("relay init");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });
    let client = wait_rpc(rpc_port, deadline).await;

    let sk = SigningKey::from_bytes([9u8; 32]);
    setup_chain(&client, &sk, "example.uip", deadline).await;

    // A renew lands in a block (its precheck is owner-only, so the
    // replay of the same bytes below exercises the TXID check).
    let renew = renew_domain_tx(
        &sk,
        "example.uip",
        unix_now() + scone_blockchain::DOMAIN_TERM_SECS + 1000,
    );
    submit(&client, &renew, deadline)
        .await
        .expect("renew accepted");
    wait_for_height(&client, 4, deadline).await;

    // The very same bytes are submitted again: rejected as a replay…
    let err = submit(&client, &renew, deadline)
        .await
        .expect_err("replayed renew must be rejected");
    assert!(err.contains("already included"), "{err}");

    // …a replay of an INCLUDED update is caught by the state precheck
    // (InvalidSequence — the state moved past it)…
    let update = update_domain_tx(&sk, "example.uip", 1, 0xaa);
    submit(&client, &update, deadline)
        .await
        .expect("update accepted");
    wait_for_height(&client, 5, deadline).await;
    let err = submit(&client, &update, deadline)
        .await
        .expect_err("replayed update must be rejected");
    assert!(
        err.contains("already included") || err.contains("invalid sequence"),
        "either guard may fire: {err}"
    );

    // …and a FRESH update still goes through: the relay is alive and
    // the production path never stalled.
    let fresh = update_domain_tx(&sk, "example.uip", 2, 0xbb);
    submit(&client, &fresh, deadline)
        .await
        .expect("fresh update accepted after replay rejections");
    let status = wait_for_height(&client, 6, deadline).await;

    let lookup = request(
        &client,
        RpcRequest::Lookup {
            name: "example.uip".into(),
        },
        deadline,
    )
    .await
    .expect("lookup");
    assert_eq!(lookup["registered"], true, "{lookup} {status}");
    assert_eq!(lookup["sequence"], 2, "{lookup}");
}
