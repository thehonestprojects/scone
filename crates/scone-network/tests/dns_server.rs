//! Real M6 integration test: one relay with its UDP DNS surface
//! enabled, driven end to end — register a domain, publish a
//! chain-committed DNS record, then query the DNS server through a
//! real UDP socket and check the verified answers.
//!
//! Scenario (M6 acceptance criteria):
//!
//! 1. relay starts with `dns_addr` on a dynamic localhost port
//!    (fallback upstreams: a local mock, second phase);
//! 2. `Register` + `Update` (record hash) txs are submitted through
//!    the control RPC; the devnet producer mines them;
//! 3. the signed record is published in the DHT (`PutRecord`);
//! 4. a real UDP query `A example.uip` returns the chain-verified
//!    address; `AAAA` returns NODATA; an unknown `.uip` name returns
//!    NXDOMAIN; a non-Scone name returns REFUSED (no upstream);
//! 5. with the mock upstream configured (phase 2 relay), a non-Scone
//!    name is forwarded and its answer returned;
//! 6. negative + positive caching are observed indirectly (identical
//!    answers on immediate re-query) — the bounded cache is covered
//!    by unit tests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use scone_core::{
    DnsRecord, DomainId, DomainName, OwnerId, Proof, PublicKeyRef, RecordData, RecordHash,
    Register, Transaction, Update,
};
use scone_crypto::{Signature, SigningKey};
use scone_network::rpc::{RpcClient, RpcRequest, RpcResponse};
use scone_network::{Config, Relay};
use scone_protocol::{encode_to_vec, signing_payload};

const TEST_BUDGET: Duration = Duration::from_secs(120);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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

fn signed_record(sk: &SigningKey, name: &str, sequence: u64) -> scone_core::SignedDnsRecord {
    let record = DnsRecord {
        domain_id: DomainId::from_name(&DomainName::new(name).expect("valid name")),
        sequence,
        expiration: 0,
        records: vec![
            RecordData::A("192.0.2.77".parse().expect("ipv4")),
            RecordData::Txt("m6 integration".into()),
        ],
    };
    let payload = encode_to_vec(&record).expect("canonical encode");
    scone_core::SignedDnsRecord {
        record,
        owner: owner_of(sk),
        signature: scone_core::Signature::from_bytes(sk.sign(&payload).to_bytes().to_vec()),
    }
}

async fn free_udp_port() -> u16 {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp probe");
    sock.local_addr().expect("addr").port()
}

async fn free_tcp_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("tcp probe");
    listener.local_addr().expect("addr").port()
}

/// One real DNS query over UDP (retry loop: the server may still be
/// warming up its RPC handshake).
async fn dns_query(
    socket: &tokio::net::UdpSocket,
    server: SocketAddr,
    id: u16,
    name: &str,
    qtype: u16,
    deadline: tokio::time::Instant,
) -> Vec<u8> {
    let mut q = vec![0u8; 12];
    q[0..2].copy_from_slice(&id.to_be_bytes());
    q[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD
    q[4..6].copy_from_slice(&1u16.to_be_bytes());
    for label in name.split('.') {
        q.push(u8::try_from(label.len()).expect("label"));
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    loop {
        socket.send_to(&q, server).await.expect("send dns");
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                buf.truncate(n);
                return buf;
            }
            _ => {
                assert!(tokio::time::Instant::now() < deadline, "dns query timeout");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

fn rcode_of(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[2], resp[3]]) & 0x000F
}

fn ancount_of(resp: &[u8]) -> u16 {
    u16::from_be_bytes([resp[6], resp[7]])
}

/// First answer rdata of a single-question uncompressed response.
fn first_rdata(resp: &[u8]) -> Vec<u8> {
    let mut i = 12;
    while resp[i] != 0 {
        i += 1 + resp[i] as usize;
    }
    i += 5;
    // first answer
    while resp[i] != 0 {
        i += 1 + resp[i] as usize;
    }
    i += 1;
    let rdlen = u16::from_be_bytes([resp[i + 8], resp[i + 9]]) as usize;
    resp[i + 10..i + 10 + rdlen].to_vec()
}

async fn wait_rpc(port: u16, deadline: tokio::time::Instant) -> RpcClient {
    let client = RpcClient::new(SocketAddr::from(([127, 0, 0, 1], port)));
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
) -> serde_json::Value {
    loop {
        match client.request(req.clone()).await {
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
        let status = request(client, RpcRequest::Status, deadline).await;
        if status["height"].as_u64() == Some(height) {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "height {height} not reached"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_server_serves_verified_records_over_udp() {
    let deadline = tokio::time::Instant::now() + TEST_BUDGET;

    // ---- mock upstream (phase 2: fallback) -------------------------
    let upstream_sock = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("upstream bind"),
    );
    let upstream_addr = upstream_sock.local_addr().expect("upstream addr");
    let upstream = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, peer) = upstream_sock
            .recv_from(&mut buf)
            .await
            .expect("upstream recv");
        let mut resp = buf[..n].to_vec();
        resp[2] |= 0x80; // QR
        resp[3] = 0; // NOERROR
        resp[7] = 1; // ANCOUNT
        resp.extend_from_slice(&[0]); // root name
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
        resp.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34
        upstream_sock
            .send_to(&resp, peer)
            .await
            .expect("upstream send");
    });

    // ---- relay with the DNS surface enabled -------------------------
    let dir = tempfile::tempdir().expect("tempdir");
    let rpc_port = free_tcp_port().await;
    let dns_port = free_udp_port().await;
    let dns_addr = SocketAddr::from(([127, 0, 0, 1], dns_port));
    let mut config = Config::new(dir.path().to_path_buf());
    config.produce_interval = Duration::from_secs(1);
    config.rpc_addr = SocketAddr::from(([127, 0, 0, 1], rpc_port));
    config.dns_addr = Some(dns_addr);
    config.dns_upstreams = vec![upstream_addr.to_string()];
    let relay = Relay::new(config).expect("relay init");
    tokio::spawn(async move {
        if let Err(e) = relay.run().await {
            eprintln!("relay ended: {e}");
        }
    });

    let client = wait_rpc(rpc_port, deadline).await;

    // ---- register + commit a record hash ----------------------------
    let sk = SigningKey::from_bytes([9u8; 32]);
    let name = "example.uip";
    let tx_hex = hex(&encode_to_vec(&register_tx(&sk, name)).expect("encode"));
    let resp = request(&client, RpcRequest::SubmitTx { tx_hex }, deadline).await;
    assert!(resp["txid"].is_string(), "{resp}");
    wait_for_height(&client, 1, deadline).await;

    let record = signed_record(&sk, name, 1);
    let expected_hash = *scone_protocol::record_hash(&record.record).as_bytes();
    let upd_hex = hex(&encode_to_vec(&update_tx(&sk, name, 1, expected_hash)).expect("encode"));
    let resp = request(&client, RpcRequest::SubmitTx { tx_hex: upd_hex }, deadline).await;
    assert!(resp["txid"].is_string(), "{resp}");
    wait_for_height(&client, 2, deadline).await;

    // Publish the signed record (DHT + local cache).
    let record_hex = hex(&encode_to_vec(&record).expect("encode record"));
    let resp = request(&client, RpcRequest::PutRecord { record_hex }, deadline).await;
    assert!(resp["published"].is_string(), "{resp}");

    // ---- real UDP DNS queries ----------------------------------------
    let qsock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("query socket");

    // A: the chain-verified address.
    let resp = dns_query(&qsock, dns_addr, 0x0001, name, 1, deadline).await;
    assert_eq!(rcode_of(&resp), 0, "NOERROR");
    assert_eq!(ancount_of(&resp), 1, "one A answer");
    assert_eq!(first_rdata(&resp), vec![192, 0, 2, 77]);
    assert_eq!(resp[2] & 0x04, 0x04, "AA bit set (authoritative)");
    // The question is echoed.
    assert_eq!(&resp[12..18], &[7, b'e', b'x', b'a', b'm', b'p']);

    // TXT: also in the set.
    let resp = dns_query(&qsock, dns_addr, 0x0002, name, 16, deadline).await;
    assert_eq!(rcode_of(&resp), 0);
    assert_eq!(ancount_of(&resp), 1, "one TXT answer");
    assert_eq!(first_rdata(&resp)[0] as usize, "m6 integration".len());

    // AAAA: published set has none → NODATA (NOERROR, 0 answers).
    let resp = dns_query(&qsock, dns_addr, 0x0003, name, 28, deadline).await;
    assert_eq!(rcode_of(&resp), 0, "NODATA is NOERROR");
    assert_eq!(ancount_of(&resp), 0);

    // Unknown Scone name → NXDOMAIN (chain is authority: a valid
    // Scone-charset name that is not registered is authoritatively
    // absent).
    let resp = dns_query(&qsock, dns_addr, 0x0004, "absent.uip", 1, deadline).await;
    assert_eq!(rcode_of(&resp), 3, "NXDOMAIN");

    // Structurally non-Scone name (underscore TLD: cannot ever be
    // registered) → forwarded to the mock upstream.
    let resp = dns_query(&qsock, dns_addr, 0x0005, "www.foo_bar", 1, deadline).await;
    assert_eq!(rcode_of(&resp), 0, "fallback NOERROR");
    assert_eq!(first_rdata(&resp), vec![93, 184, 216, 34]);
    upstream.await.expect("upstream served one query");

    // Immediate re-query of the A record: still correct (cache path
    // or fresh resolution — both must be verified-identical).
    let resp = dns_query(&qsock, dns_addr, 0x0006, name, 1, deadline).await;
    assert_eq!(ancount_of(&resp), 1);
    assert_eq!(first_rdata(&resp), vec![192, 0, 2, 77]);

    // Sub-name hits the apex's records.
    let resp = dns_query(&qsock, dns_addr, 0x0007, "www.example.uip", 1, deadline).await;
    assert_eq!(rcode_of(&resp), 0, "subname via apex");
    assert_eq!(first_rdata(&resp), vec![192, 0, 2, 77]);
}
