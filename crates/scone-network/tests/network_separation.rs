//! M8b acceptance: network separation at the relay level.
//!
//! 1. a transaction built for another network is refused with the
//!    typed `WrongNetwork` error at submit (never pooled, never
//!    relayed) — and the relay stays alive;
//! 2. the status RPC exposes the relay's network id;
//! 3. a relay configured for mainnet refuses a testnet tx and vice
//!    versa;
//! 4. testnet PoW difficulties are symbolic (a claim mines in ms).

use std::time::Duration;

use scone_core::{MAINNET, NetworkParams, Proof, RegisterTld, TESTNET, TldName, Transaction};
use scone_crypto::{Signature, SigningKey};
use scone_network::{Config, Relay, RpcClient, RpcRequest, RpcResponse};
use std::net::SocketAddr;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Signs a RegisterTld built for `network` with an EMPTY proof: the
/// network check must fire before any PoW work.
fn foreign_register_tld(network: scone_core::NetworkId, sk: &SigningKey) -> Transaction {
    let unsigned = Transaction::RegisterTld(RegisterTld::register_tld_on(
        network,
        TldName::new("uip").unwrap(),
        1,
        Proof::from_bytes(Vec::new()),
        sk.public_key(),
        Signature::from_bytes([0; 64]),
    ));
    let payload = scone_protocol::signing_payload(&unsigned).unwrap();
    match unsigned {
        Transaction::RegisterTld(mut t) => {
            t.signature = sk.sign(&payload);
            Transaction::RegisterTld(t)
        }
        _ => unreachable!(),
    }
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_network_tx_is_refused_typed_and_non_fatal() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    // A MAINNET relay (its own data dir — storage is per-network).
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port().await;
    let mut config = Config::new(dir.path().to_path_buf());
    config.network = MAINNET;
    config.rpc_addr = SocketAddr::from(([127, 0, 0, 1], rpc_port));
    let relay = Relay::new(config).expect("mainnet relay init");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });

    // Wait for the RPC surface.
    let client = RpcClient::new(SocketAddr::from(([127, 0, 0, 1], rpc_port)));
    loop {
        if let Ok(RpcResponse::Ok { .. }) = client.request(RpcRequest::Status).await {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "rpc never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Status exposes the network id.
    let status = client.request(RpcRequest::Status).await.unwrap();
    let RpcResponse::Ok { data } = status else {
        panic!("status failed");
    };
    assert_eq!(data["network"], "scone-mainnet", "{data}");

    // A TESTNET tx is refused with the typed WrongNetwork message…
    let sk = SigningKey::from_bytes([0x55; 32]);
    let tx = foreign_register_tld(TESTNET.network_id, &sk);
    let tx_hex = hex(&scone_protocol::encode_to_vec(&tx).unwrap());
    let resp = client
        .request(RpcRequest::SubmitTx { tx_hex })
        .await
        .unwrap();
    match resp {
        RpcResponse::Error { message } => {
            assert!(
                message.contains("wrong network"),
                "expected a WrongNetwork rejection, got: {message}"
            );
            assert!(
                message.contains("scone-testnet") && message.contains("scone-mainnet"),
                "the message names both networks: {message}"
            );
        }
        RpcResponse::Ok { data } => panic!("testnet tx accepted by a mainnet relay: {data}"),
    }

    // …and the relay is still alive afterwards.
    let status = client.request(RpcRequest::Status).await.unwrap();
    let RpcResponse::Ok { data } = status else {
        panic!("relay died after the wrong-network tx");
    };
    assert_eq!(data["height"], 0, "no block from a foreign tx: {data}");
    assert_eq!(data["mempool"], 0, "nothing pooled: {data}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn testnet_relay_refuses_a_mainnet_tx() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

    // Default (testnet) relay.
    let dir = tempfile::tempdir().unwrap();
    let rpc_port = free_port().await;
    let mut config = Config::new(dir.path().to_path_buf());
    config.rpc_addr = SocketAddr::from(([127, 0, 0, 1], rpc_port));
    let relay = Relay::new(config).expect("testnet relay init");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });

    let client = RpcClient::new(SocketAddr::from(([127, 0, 0, 1], rpc_port)));
    loop {
        if let Ok(RpcResponse::Ok { .. }) = client.request(RpcRequest::Status).await {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "rpc never came up");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let sk = SigningKey::from_bytes([0x66; 32]);
    let tx = foreign_register_tld(MAINNET.network_id, &sk);
    let tx_hex = hex(&scone_protocol::encode_to_vec(&tx).unwrap());
    let resp = client
        .request(RpcRequest::SubmitTx { tx_hex })
        .await
        .unwrap();
    match resp {
        RpcResponse::Error { message } => {
            assert!(message.contains("wrong network"), "{message}");
        }
        RpcResponse::Ok { data } => panic!("mainnet tx accepted by a testnet relay: {data}"),
    }
}

#[test]
fn testnet_difficulties_are_symbolical() {
    // M8b acceptance: a testnet PoW mines in milliseconds — a few
    // hundred hashes at most (2^-8 per draw for a TLD).
    let start = std::time::Instant::now();
    let mut challenge = Vec::new();
    challenge.extend_from_slice(scone_core::id::TLD_ID_VERSION);
    challenge.extend_from_slice(b"mine-fast");
    let checked = scone_core::pow::mine(TESTNET.network_id, &challenge, TESTNET.tld_pow_difficulty);
    let elapsed = start.elapsed();
    assert!(checked.nonce < 4096, "{checked:?}");
    assert!(
        elapsed < Duration::from_millis(500),
        "testnet TLD PoW took {elapsed:?}"
    );

    let mut challenge = Vec::new();
    challenge.extend_from_slice(scone_core::id::DOMAIN_ID_VERSION);
    challenge.extend_from_slice(b"mine-fast.uip");
    let checked = scone_core::pow::mine(
        TESTNET.network_id,
        &challenge,
        TESTNET.domain_pow_difficulty,
    );
    assert!(checked.nonce < 512, "{checked:?}");

    // Sanity: the named instances differ and are the documented ones.
    assert_eq!(NetworkParams::by_name("testnet").unwrap(), TESTNET);
    assert_eq!(NetworkParams::by_name("mainnet").unwrap(), MAINNET);
}
