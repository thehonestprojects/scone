//! End-to-end M5 test: the REAL `scone` binary, TWO relay processes
//! (node A + node B bootstrapped on A) driven exclusively through the
//! CLI command surface — no in-process types.
//!
//! Scenario (M5 acceptance criteria):
//!
//! 1. `scone relay` A (rpc 127.0.0.1:a) and B (rpc 127.0.0.1:b,
//!    `--bootstrap` on A's announced p2p address) as child processes;
//! 2. `scone identity generate` → `scone domain register` (signed,
//!    one command) against A; both nodes sync the block;
//! 3. a DNS record FILE drives `scone domain update` against B
//!    (signed, sequence + record hash derived from the file, tx
//!    submitted, record published to the DHT);
//! 4. `scone domain info` at B shows the on-chain state and the
//!    chain-valid DNS records; `scone record get` at A resolves the
//!    record B published, through the DHT;
//! 5. `scone domain register` of an already-taken name fails with a
//!    clean error; `domain update` with a non-owner identity fails;
//!    a malformed record file fails locally without touching the
//!    chain.
//!
//! The whole scenario must complete inside TEST_BUDGET.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Total budget for the whole scenario (hard stop).
const TEST_BUDGET: Duration = Duration::from_secs(240);

/// Binary under test (the crate itself).
const BIN: &str = env!("CARGO_BIN_EXE_scone");

/// A running relay child process; kills it on drop.
struct RelayProcess {
    child: Child,
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Grabs a free localhost TCP port (bind + drop).
fn free_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("port probe");
    listener.local_addr().expect("local addr").port()
}

/// Spawns the `scone` binary with these args, capturing stdout.
fn run_scone(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN)
        .args(args)
        .env_remove("SCONE_KAD_DEBUG")
        .output()
        .expect("spawn scone binary");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stdout, stderr)
}

/// Like [`run_scone`] but asserts success and returns stdout lines.
fn scone_ok(args: &[&str]) -> Vec<String> {
    let (ok, stdout, stderr) = run_scone(args);
    assert!(
        ok,
        "scone {:?} failed\nstdout:\n{stdout}\nstderr:\n{stderr}",
        args
    );
    stdout.lines().map(String::from).collect()
}

/// Runs a command expected to FAIL; returns the combined error text.
fn scone_err(args: &[&str]) -> String {
    let (ok, stdout, stderr) = run_scone(args);
    assert!(!ok, "scone {:?} unexpectedly succeeded:\n{stdout}", args);
    format!("{stdout}{stderr}")
}

/// Reads one file fully (for drain helper).
fn read_all(path: &Path) -> String {
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|mut f| f.read_to_string(&mut text))
        .expect("read file");
    text
}

/// Spawns a relay and waits for its RPC to answer `status`.
fn start_relay(data_dir: &Path, rpc: SocketAddr, bootstrap: Option<&str>) -> RelayProcess {
    let log_path = data_dir.with_extension("relay.log");
    let log = std::fs::File::create(&log_path).expect("create relay log");
    let mut command = Command::new(BIN);
    command
        .args([
            "relay",
            "--data-dir",
            data_dir.to_str().expect("utf8 data dir"),
            "--rpc",
            &rpc.to_string(),
        ])
        .stdout(Stdio::from(log.try_clone().expect("clone log")))
        .stderr(Stdio::from(log));
    if let Some(addr) = bootstrap {
        command.args(["--bootstrap", addr]);
    }
    let mut child = command.spawn().expect("spawn relay");
    // Wait for the RPC surface (status must succeed).
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            child.try_wait().expect("relay state").is_none(),
            "relay died at startup"
        );
        let (ok, _, _) = run_scone(&["status", "--rpc", &rpc.to_string()]);
        if ok {
            return RelayProcess { child };
        }
        assert!(Instant::now() < deadline, "relay rpc never came up");
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Extracts A's bootstrap multiaddr from its stdout line `p2p: <addr>`
/// (stdout and stderr are both redirected into the same log file; the
/// data line is matched by prefix, log lines start with a timestamp).
fn bootstrap_of(log_path: &Path, rpc: SocketAddr) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = read_all(log_path);
        for line in log.lines() {
            if let Some(index) = line.find("p2p: ") {
                return line[index + "p2p: ".len()..].trim().to_string();
            }
        }
        assert!(
            Instant::now() < deadline,
            "relay {rpc} never announced its p2p address (log: {})",
            read_all(log_path)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits until `pred(lines)` holds on `scone <base args>` output.
fn wait_cli(base: &[&str], pred: impl Fn(&[String]) -> bool, what: &str) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let lines = scone_ok(base);
        if pred(&lines) {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}; last output:\n{}",
            lines.join("\n")
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// `status --rpc R` parsed into (height, peers).
fn status(rpc: &SocketAddr) -> (u64, u64) {
    let lines = scone_ok(&["status", "--rpc", &rpc.to_string()]);
    let get = |key: &str| -> u64 {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(&format!("{key}: ")))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (get("height"), get("peers"))
}

#[test]
fn two_nodes_cli_end_to_end() {
    let deadline = Instant::now() + TEST_BUDGET;
    let work = tempfile::tempdir().expect("workdir");
    let node_a_dir = work.path().join("node-a");
    let node_b_dir = work.path().join("node-b");
    std::fs::create_dir_all(&node_a_dir).expect("mkdir a");
    std::fs::create_dir_all(&node_b_dir).expect("mkdir b");

    let rpc_a = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
    let rpc_b = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));

    // Keystore shared by both CLI invocations.
    let keys = work.path().join("keys");
    std::fs::create_dir_all(&keys).expect("mkdir keys");
    let pass_var = "SCONE_TEST_PASS_E2E";
    // SAFETY: single-threaded test.
    unsafe { std::env::set_var(pass_var, "e2e-passphrase") };
    let identity = |name: &str| -> Vec<String> {
        scone_ok(&[
            "identity",
            "generate",
            "--name",
            name,
            "--dir",
            keys.to_str().expect("utf8 keys"),
            "--passphrase-env",
            pass_var,
        ]);
        vec![
            "--identity".to_string(),
            name.to_string(),
            "--dir".to_string(),
            keys.to_str().expect("utf8 keys").to_string(),
            "--passphrase-env".to_string(),
            pass_var.to_string(),
        ]
    };

    // ---- node A, then node B bootstrapped on A -------------------
    let relay_a = start_relay(&node_a_dir, rpc_a, None);
    let bootstrap = bootstrap_of(&work.path().join("node-a.relay.log"), rpc_a);
    assert!(
        bootstrap.ends_with(&format!("/p2p/{}", peer_id_of(&rpc_a))),
        "bootstrap addr carries the peer id: {bootstrap}"
    );
    let relay_b = start_relay(&node_b_dir, rpc_b, Some(&bootstrap));

    // Wait for the mesh: both nodes see one peer.
    let _mesh_deadline = deadline;
    wait_cli(
        &["status", "--rpc", &rpc_a.to_string()],
        |l| l.iter().any(|x| x == "peers: 1"),
        "A connected to B",
    );
    wait_cli(
        &["status", "--rpc", &rpc_b.to_string()],
        |l| l.iter().any(|x| x == "peers: 1"),
        "B connected to A",
    );

    // ---- register via one signed command (against A) --------------
    let id_alice = identity("alice");
    let name = "e2e.uip";
    let reg = scone_ok(&[
        "domain",
        "register",
        name,
        "--identity",
        &id_alice[1],
        "--dir",
        &id_alice[3],
        "--passphrase-env",
        &id_alice[5],
        "--rpc",
        &rpc_a.to_string(),
    ]);
    assert!(
        reg.iter()
            .any(|l| l.starts_with("registering ") && l.contains("owner ")),
        "register output: {reg:?}"
    );
    assert!(reg.iter().any(|l| l.starts_with("txid: ")));
    assert!(
        reg.iter().any(|l| l.starts_with("confirmed: height ")),
        "registration confirmed: {reg:?}"
    );

    // Both nodes at height 1 with the domain registered.
    wait_cli(
        &["status", "--rpc", &rpc_a.to_string()],
        |l| l.iter().any(|x| x == "height: 1"),
        "A at height 1",
    );
    wait_cli(
        &["status", "--rpc", &rpc_b.to_string()],
        |l| l.iter().any(|x| x == "height: 1"),
        "B synced height 1",
    );
    let lookup_b = scone_ok(&["lookup", name, "--rpc", &rpc_b.to_string()]);
    assert!(
        lookup_b.iter().any(|l| l == "registered: true"),
        "{lookup_b:?}"
    );

    // ---- record file drives domain update (against B) -------------
    let record_file = work.path().join("records.txt");
    std::fs::write(
        &record_file,
        "# e2e record set\nA 192.0.2.10\nAAAA 2001:db8::10\nTXT hello from the e2e test\n",
    )
    .expect("write record file");
    let upd = scone_ok(&[
        "domain",
        "update",
        name,
        "--file",
        record_file.to_str().expect("utf8 record file"),
        "--identity",
        &id_alice[1],
        "--dir",
        &id_alice[3],
        "--passphrase-env",
        &id_alice[5],
        "--rpc",
        &rpc_b.to_string(),
    ]);
    assert!(
        upd.iter()
            .any(|l| l.starts_with("updating ") && l.contains("sequence 1")),
        "update output: {upd:?}"
    );
    assert!(upd.iter().any(|l| l.starts_with("record hash: ")));
    assert!(
        upd.iter().any(|l| l == "record published in the DHT"),
        "record published: {upd:?}"
    );

    // Both nodes at height 2.
    wait_cli(
        &["status", "--rpc", &rpc_a.to_string()],
        |l| l.iter().any(|x| x == "height: 2"),
        "A at height 2",
    );
    wait_cli(
        &["status", "--rpc", &rpc_b.to_string()],
        |l| l.iter().any(|x| x == "height: 2"),
        "B at height 2",
    );

    // ---- domain info at B: chain state + DNS records ---------------
    let info_b = scone_ok(&["domain", "info", name, "--rpc", &rpc_b.to_string()]);
    for expected in [
        "registered: true",
        "sequence: 1",
        "  A 192.0.2.10",
        "  AAAA 2001:db8::10",
        "  TXT hello from the e2e test",
    ] {
        assert!(
            info_b.iter().any(|l| l == expected),
            "domain info must contain '{expected}':\n{}",
            info_b.join("\n")
        );
    }

    // ---- record get at A: DHT resolution across nodes ---------------
    let deadline_get = Instant::now() + Duration::from_secs(60);
    let resolved = loop {
        let lines = scone_ok(&["record", "get", name, "--rpc", &rpc_a.to_string()]);
        if lines.iter().any(|l| l == "verified: true") {
            break lines;
        }
        assert!(
            Instant::now() < deadline_get,
            "record never resolvable at A"
        );
        std::thread::sleep(Duration::from_millis(400));
    };
    assert!(
        resolved.iter().any(|l| l.starts_with("record: ")),
        "{resolved:?}"
    );

    // Unregistered domain: info says so, no DNS data.
    let info_free = scone_ok(&["domain", "info", "free.uip", "--rpc", &rpc_a.to_string()]);
    assert!(
        info_free.iter().any(|l| l == "registered: false"),
        "{info_free:?}"
    );

    // ---- error paths -------------------------------------------------
    // Second register of a taken name: clean typed failure.
    let err = scone_err(&[
        "domain",
        "register",
        name,
        "--identity",
        &id_alice[1],
        "--dir",
        &id_alice[3],
        "--passphrase-env",
        &id_alice[5],
        "--rpc",
        &rpc_a.to_string(),
    ]);
    assert!(err.contains("already registered"), "err: {err}");

    // UpdateDomain with a NON-owner identity: refused before touching the chain.
    let id_bob = identity("bob");
    let err = scone_err(&[
        "domain",
        "update",
        name,
        "--file",
        record_file.to_str().expect("utf8 record file"),
        "--identity",
        &id_bob[1],
        "--dir",
        &id_bob[3],
        "--passphrase-env",
        &id_bob[5],
        "--rpc",
        &rpc_a.to_string(),
    ]);
    assert!(err.contains("not the owner"), "err: {err}");

    // Malformed record file: local parse failure, chain untouched.
    let bad_file = work.path().join("bad-records.txt");
    std::fs::write(&bad_file, "BOGUS 1.2.3.4\n").expect("write bad file");
    scone_err(&[
        "domain",
        "update",
        name,
        "--file",
        bad_file.to_str().expect("utf8 bad file"),
        "--identity",
        &id_alice[1],
        "--dir",
        &id_alice[3],
        "--passphrase-env",
        &id_alice[5],
        "--rpc",
        &rpc_a.to_string(),
    ]);
    // Empty record file: rejected (empty sets are invalid).
    let empty_file = work.path().join("empty-records.txt");
    std::fs::write(&empty_file, "# only a comment\n").expect("write empty file");
    scone_err(&[
        "domain",
        "update",
        name,
        "--file",
        empty_file.to_str().expect("utf8 empty file"),
        "--identity",
        &id_alice[1],
        "--dir",
        &id_alice[3],
        "--passphrase-env",
        &id_alice[5],
        "--rpc",
        &rpc_a.to_string(),
    ]);
    // UpdateDomain of an unregistered domain: refused.
    scone_err(&[
        "domain",
        "update",
        "free.uip",
        "--file",
        record_file.to_str().expect("utf8 record file"),
        "--identity",
        &id_alice[1],
        "--dir",
        &id_alice[3],
        "--passphrase-env",
        &id_alice[5],
        "--rpc",
        &rpc_a.to_string(),
    ]);

    // Failed updates touched nothing: still height 2 everywhere.
    let (height_a, _) = status(&rpc_a);
    let (height_b, _) = status(&rpc_b);
    assert_eq!(
        (height_a, height_b),
        (2, 2),
        "failed updates must not produce blocks"
    );

    drop(relay_b);
    drop(relay_a);
}

/// Reads the peer id of the relay at `rpc` from `status`.
fn peer_id_of(rpc: &SocketAddr) -> String {
    let lines = scone_ok(&["status", "--rpc", &rpc.to_string()]);
    lines
        .iter()
        .find_map(|l| l.strip_prefix("peer_id: "))
        .expect("peer_id line")
        .to_string()
}
