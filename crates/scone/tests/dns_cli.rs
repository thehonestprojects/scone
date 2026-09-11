//! End-to-end M6 test: the REAL `scone` binary as a relay with its
//! UDP DNS surface enabled, queried through the real `scone dig`
//! command. No in-process types.
//!
//! Scenario:
//!
//! 1. `scone relay --dns 127.0.0.1:<port>` as a child process;
//! 2. `scone identity generate` + `scone domain register` (signed,
//!    one command) + `scone domain update --file` (commits the record
//!    hash and publishes the record in the DHT);
//! 3. `scone dig <name> --dns 127.0.0.1:<port>` returns the
//!    chain-verified A record over a real UDP round trip;
//! 4. `scone dig absent.uip` gets NXDOMAIN (status 3);
//! 5. `scone dig www.example` (structurally non-Scone) gets REFUSED
//!    (status 5) — no fallback upstream configured.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TEST_BUDGET: Duration = Duration::from_secs(180);
const BIN: &str = env!("CARGO_BIN_EXE_scone");

fn free_tcp_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("port probe");
    listener.local_addr().expect("addr").port()
}

fn free_udp_port() -> u16 {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("udp probe");
    sock.local_addr().expect("addr").port()
}

fn run_scone(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(BIN).args(args).output().expect("spawn scone");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn scone_ok(args: &[&str]) -> Vec<String> {
    let (ok, stdout, stderr) = run_scone(args);
    assert!(
        ok,
        "scone {args:?} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    stdout.lines().map(String::from).collect()
}

fn read_all(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read log")
}

/// Waits for the `dns: <addr>` data line in the relay's log.
fn dns_addr_of(log_path: &Path) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        for line in read_all(log_path).lines() {
            if let Some(rest) = line.strip_prefix("dns: ")
                && let Ok(addr) = rest.trim().parse()
            {
                return addr;
            }
        }
        assert!(
            Instant::now() < deadline,
            "relay never announced dns: (log: {})",
            read_all(log_path)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn dns_cli_end_to_end() {
    let _deadline = Instant::now() + TEST_BUDGET;
    let work = tempfile::tempdir().expect("workdir");
    let node_dir = work.path().join("node");
    std::fs::create_dir_all(&node_dir).expect("mkdir");

    let rpc = SocketAddr::from((Ipv4Addr::LOCALHOST, free_tcp_port()));
    let dns = SocketAddr::from((Ipv4Addr::LOCALHOST, free_udp_port()));

    // ---- relay with the DNS surface --------------------------------
    let log_path = work.path().with_extension("relay.log");
    let log = std::fs::File::create(&log_path).expect("log");
    let mut command = Command::new(BIN);
    command
        .args([
            "relay",
            "--data-dir",
            node_dir.to_str().expect("dir"),
            "--rpc",
            &rpc.to_string(),
            "--dns",
            &dns.to_string(),
        ])
        .stdout(Stdio::from(log.try_clone().expect("clone")))
        .stderr(Stdio::from(log));
    let child = command.spawn().expect("spawn relay");
    // Read the announced DNS address while the child runs.
    let dns_addr = dns_addr_of(&log_path);
    assert_eq!(dns_addr, dns, "announced dns address matches --dns");
    let relay_guard = RelayGuard { child };

    // Wait for the RPC surface.
    let up = Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, _, _) = run_scone(&["status", "--rpc", &rpc.to_string()]);
        if ok {
            break;
        }
        assert!(Instant::now() < up, "relay rpc never came up");
        std::thread::sleep(Duration::from_millis(150));
    }

    // ---- identity + TLD claim + register + update ------------------
    let keys = work.path().join("keys");
    let pass_var = "SCONE_TEST_PASS_M6";
    // SAFETY: single-threaded test.
    unsafe { std::env::set_var(pass_var, "m6-passphrase") };
    scone_ok(&[
        "identity",
        "generate",
        "--name",
        "owner",
        "--dir",
        keys.to_str().expect("keys"),
        "--passphrase-env",
        pass_var,
    ]);
    let id_args = [
        "--identity".to_string(),
        "owner".to_string(),
        "--dir".to_string(),
        keys.to_str().expect("keys").to_string(),
        "--passphrase-env".to_string(),
        pass_var.to_string(),
    ];

    // ---- claim the TLD namespace (D1, M7c) ------------------------
    // `scone tld register` arrives in M7e; until then the e2e path is
    // the offline tx surface: build → sign → submit.
    let tld_payload = scone_ok(&[
        "tx",
        "build",
        "register-tld",
        "--tld",
        "uip",
        "--timestamp",
        "42",
    ])
    .into_iter()
    .find_map(|l| l.strip_prefix("signing payload: ").map(String::from))
    .expect("signing payload line");
    let tld_signed = scone_ok(&[
        "tx",
        "sign",
        &tld_payload,
        "--identity",
        "owner",
        "--dir",
        keys.to_str().expect("keys"),
        "--passphrase-env",
        pass_var,
    ])
    .into_iter()
    .find_map(|l| l.strip_prefix("transaction: ").map(String::from))
    .expect("signed transaction line");
    scone_ok(&[
        "submit",
        "tx",
        "--hex",
        &tld_signed,
        "--rpc",
        &rpc.to_string(),
    ]);
    let tld_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let lines = scone_ok(&["status", "--rpc", &rpc.to_string()]);
        if lines.iter().any(|l| l.starts_with("height: 1")) {
            break;
        }
        assert!(Instant::now() < tld_deadline, "tld claim never mined");
        std::thread::sleep(Duration::from_millis(300));
    }

    let name = "m6.uip";
    let reg_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = scone_ok(&[
            "domain",
            "register",
            name,
            &id_args[0],
            &id_args[1],
            &id_args[2],
            &id_args[3],
            &id_args[4],
            &id_args[5],
            "--rpc",
            &rpc.to_string(),
        ]);
        if out.iter().any(|l| l.starts_with("confirmed: height ")) {
            break;
        }
        assert!(Instant::now() < reg_deadline, "register never confirmed");
        std::thread::sleep(Duration::from_millis(300));
    }

    let record_file = work.path().join("records.txt");
    std::fs::write(&record_file, "A 192.0.2.66\nTXT m6 cli e2e\n").expect("write records");
    let upd_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = scone_ok(&[
            "domain",
            "update",
            name,
            "--file",
            record_file.to_str().expect("file"),
            &id_args[0],
            &id_args[1],
            &id_args[2],
            &id_args[3],
            &id_args[4],
            &id_args[5],
            "--rpc",
            &rpc.to_string(),
        ]);
        if out.iter().any(|l| l == "record published in the DHT") {
            break;
        }
        assert!(Instant::now() < upd_deadline, "update never confirmed");
        std::thread::sleep(Duration::from_millis(300));
    }

    // ---- dig: the verified A record ----------------------------------
    let dig_deadline = Instant::now() + Duration::from_secs(30);
    let lines = loop {
        let lines = scone_ok(&["dig", name, "--dns", &dns.to_string(), "--qtype", "A"]);
        if lines.iter().any(|l| l == "answers: 1") {
            break lines;
        }
        assert!(
            Instant::now() < dig_deadline,
            "dig never answered; got: {lines:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(
        lines.iter().any(|l| l.starts_with("status: 0")),
        "NOERROR: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("rdata c0000242")), // 192.0.2.66
        "A record 192.0.2.66: {lines:?}"
    );

    // TXT round too.
    let lines = scone_ok(&["dig", name, "--dns", &dns.to_string(), "--qtype", "TXT"]);
    assert!(
        lines.iter().any(|l| l.starts_with("status: 0")),
        "{lines:?}"
    );
    assert!(lines.iter().any(|l| l == "answers: 1"), "{lines:?}");

    // Unknown Scone name → NXDOMAIN (3).
    let lines = scone_ok(&["dig", "absent.uip", "--dns", &dns.to_string()]);
    assert!(
        lines.iter().any(|l| l == "status: 3"),
        "NXDOMAIN: {lines:?}"
    );

    // Structurally non-Scone name (underscore TLD) → REFUSED (5, no upstream).
    let lines = scone_ok(&["dig", "www.foo_bar", "--dns", &dns.to_string()]);
    assert!(lines.iter().any(|l| l == "status: 5"), "REFUSED: {lines:?}");

    drop(relay_guard);
}

/// Kills the child on drop.
struct RelayGuard {
    child: Child,
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
